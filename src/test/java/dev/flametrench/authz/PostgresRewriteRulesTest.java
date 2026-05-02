// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import dev.flametrench.ids.Id;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PostgresTupleStore rewrite-rule evaluation per ADR 0017.
 *
 * <p>Mirrors the in-memory {@code RewriteRulesTest} so any drift
 * between the two implementations surfaces as a failing test. Gated on
 * {@code AUTHZ_POSTGRES_URL} — skipped entirely when unset.
 */
@EnabledIfEnvironmentVariable(named = "AUTHZ_POSTGRES_URL", matches = ".+")
class PostgresRewriteRulesTest {

    private static DataSource dataSource;
    private static String schemaSql;

    private String alice;
    private String orgAcme;
    private String proj42;

    @BeforeAll
    static void setupClass() throws IOException {
        String url = System.getenv("AUTHZ_POSTGRES_URL");
        URI uri = URI.create(url.replaceFirst("^postgresql:", "http:"));
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setServerNames(new String[] { uri.getHost() });
        ds.setPortNumbers(new int[] { uri.getPort() == -1 ? 5432 : uri.getPort() });
        String path = uri.getPath();
        ds.setDatabaseName(path != null && path.length() > 1 ? path.substring(1) : "postgres");
        if (uri.getUserInfo() != null) {
            String[] parts = uri.getUserInfo().split(":", 2);
            ds.setUser(parts[0]);
            if (parts.length > 1) ds.setPassword(parts[1]);
        }
        dataSource = ds;
        schemaSql = Files.readString(Path.of("src/test/resources/postgres-schema.sql"));
    }

    @BeforeEach
    void resetSchema() throws Exception {
        try (Connection conn = dataSource.getConnection();
             Statement st = conn.createStatement()) {
            st.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;");
            st.execute(schemaSql);
        }
        alice = registerUser();
        orgAcme = Id.generate("org").substring(4); // bare hex
        proj42 = Id.generate("org").substring(4);
    }

    private String registerUser() throws Exception {
        String wire = Id.generate("usr");
        UUID uuid = UUID.fromString(Id.decode(wire).uuid());
        try (Connection conn = dataSource.getConnection();
             var ps = conn.prepareStatement(
                     "INSERT INTO usr (id, status) VALUES (?, 'active')")) {
            ps.setObject(1, uuid);
            ps.executeUpdate();
        }
        return wire;
    }

    private static PostgresTupleStore storeWithRules(
            DataSource ds,
            Map<String, Map<String, List<RuleNode>>> rules
    ) {
        return new PostgresTupleStore(
                ds, Clock.systemUTC(), rules,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT
        );
    }

    // ─── empty rules → v0.2-equivalent ──────────────────────────

    @Test
    void emptyRules_noDerivation() {
        PostgresTupleStore store = new PostgresTupleStore(dataSource); // rules undefined
        store.createTuple("usr", alice, "editor", "proj", proj42, alice);
        CheckResult r = store.check("usr", alice, "viewer", "proj", proj42);
        assertFalse(r.allowed());
    }

    @Test
    void emptyRulesMap_noDerivation() {
        PostgresTupleStore store = storeWithRules(dataSource, Map.of());
        store.createTuple("usr", alice, "editor", "proj", proj42, alice);
        CheckResult r = store.check("usr", alice, "viewer", "proj", proj42);
        assertFalse(r.allowed());
    }

    // ─── computed_userset ──────────────────────────────────────

    @Test
    void computedUserset_editorImpliesViewer() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ThisNode(), new ComputedUserset("editor"))
                )
        );
        PostgresTupleStore store = storeWithRules(dataSource, rules);
        Tuple editor = store.createTuple("usr", alice, "editor", "proj", proj42, alice);
        CheckResult r = store.check("usr", alice, "viewer", "proj", proj42);
        assertTrue(r.allowed());
        assertEquals(editor.id(), r.matchedTupleId());
    }

    @Test
    void computedUserset_adminToViewerChain() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ThisNode(), new ComputedUserset("editor")),
                        "editor", List.of(new ThisNode(), new ComputedUserset("admin"))
                )
        );
        PostgresTupleStore store = storeWithRules(dataSource, rules);
        Tuple admin = store.createTuple("usr", alice, "admin", "proj", proj42, alice);
        CheckResult r = store.check("usr", alice, "viewer", "proj", proj42);
        assertTrue(r.allowed());
        assertEquals(admin.id(), r.matchedTupleId());
    }

    // ─── tuple_to_userset ──────────────────────────────────────

    @Test
    void tupleToUserset_orgAdminImpliesProjAdmin() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "admin", List.of(
                                new ThisNode(),
                                new TupleToUserset("parent_org", "admin")
                        )
                )
        );
        PostgresTupleStore store = storeWithRules(dataSource, rules);
        Tuple orgAdmin = store.createTuple("usr", alice, "admin", "org", orgAcme, alice);
        // Wire-format the org subject id so PostgresTupleStore decodes it.
        store.createTuple("org", "org_" + orgAcme, "parent_org", "proj", proj42, alice);
        CheckResult r = store.check("usr", alice, "admin", "proj", proj42);
        assertTrue(r.allowed());
        assertEquals(orgAdmin.id(), r.matchedTupleId());
    }

    @Test
    void tupleToUserset_orgMemberDoesNotImplyProjAdmin() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "admin", List.of(
                                new ThisNode(),
                                new TupleToUserset("parent_org", "admin")
                        )
                )
        );
        PostgresTupleStore store = storeWithRules(dataSource, rules);
        store.createTuple("usr", alice, "member", "org", orgAcme, alice);
        store.createTuple("org", "org_" + orgAcme, "parent_org", "proj", proj42, alice);
        CheckResult r = store.check("usr", alice, "admin", "proj", proj42);
        assertFalse(r.allowed());
    }

    // ─── cycle detection ──────────────────────────────────────

    @Test
    void selfReferentialCycle_terminatesSilently() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ThisNode(), new ComputedUserset("viewer"))
                )
        );
        PostgresTupleStore store = storeWithRules(dataSource, rules);
        CheckResult r = store.check("usr", alice, "viewer", "proj", proj42);
        assertFalse(r.allowed());
    }

    // ─── evaluation bounds ─────────────────────────────────────

    @Test
    void depthLimit_raises() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ComputedUserset("editor")),
                        "editor", List.of(new ComputedUserset("admin")),
                        "admin", List.of(new ComputedUserset("owner")),
                        "owner", List.of(new ComputedUserset("super"))
                )
        );
        PostgresTupleStore store = new PostgresTupleStore(
                dataSource, Clock.systemUTC(), rules, 2, RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT
        );
        assertThrows(EvaluationLimitExceededError.class,
                () -> store.check("usr", alice, "viewer", "proj", proj42));
    }

    // ─── checkAny ──────────────────────────────────────────────

    @Test
    void checkAny_fastPathNoRules() {
        PostgresTupleStore store = new PostgresTupleStore(dataSource);
        store.createTuple("usr", alice, "editor", "proj", proj42, alice);
        CheckResult r = store.checkAny("usr", alice, List.of("viewer", "editor"), "proj", proj42);
        assertTrue(r.allowed());
    }

    @Test
    void checkAny_withRulesEvaluatesEachInTurn() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ThisNode(), new ComputedUserset("editor"))
                )
        );
        PostgresTupleStore store = storeWithRules(dataSource, rules);
        store.createTuple("usr", alice, "editor", "proj", proj42, alice);
        CheckResult r = store.checkAny("usr", alice, List.of("admin", "viewer"), "proj", proj42);
        assertTrue(r.allowed());
    }
}
