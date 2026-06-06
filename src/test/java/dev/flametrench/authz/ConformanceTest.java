// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.postgresql.ds.PGSimpleDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Flametrench v0.1 conformance suite — Java / JUnit 5 harness for the
 * authorization capability.
 *
 * <p>Exercises check, check_any, and create_tuple (uniqueness + format)
 * against the fixture corpus vendored from
 * github.com/flametrench/spec/conformance/fixtures/authorization/.
 */
class ConformanceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode loadFixture(String relativePath) throws IOException {
        String resource = "/conformance/fixtures/" + relativePath;
        try (InputStream in = ConformanceTest.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("Fixture not found on classpath: " + resource);
            }
            return MAPPER.readTree(in);
        }
    }

    private static Class<? extends RuntimeException> errorClassForSpecName(String name) {
        return switch (name) {
            case "DuplicateTupleError" -> DuplicateTupleError.class;
            case "InvalidFormatError" -> InvalidFormatError.class;
            case "EmptyRelationSetError" -> EmptyRelationSetError.class;
            default -> throw new IllegalArgumentException("Unknown spec error: " + name);
        };
    }

    private static void seed(InMemoryTupleStore store, JsonNode given) {
        seed((TupleStore) store, given);
    }

    private static void seed(TupleStore store, JsonNode given) {
        for (JsonNode t : given) {
            store.createTuple(
                    t.get("subject_type").asText(),
                    t.get("subject_id").asText(),
                    t.get("relation").asText(),
                    t.get("object_type").asText(),
                    t.get("object_id").asText()
            );
        }
    }

    // ─── authorization.check (exact match) ───

    @TestFactory
    List<DynamicTest> checkConformance() throws IOException {
        JsonNode fixture = loadFixture("authorization/check.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode t : fixture.get("tests")) {
            String id = t.get("id").asText();
            String desc = t.get("description").asText();
            tests.add(DynamicTest.dynamicTest("[" + id + "] " + desc, () -> {
                InMemoryTupleStore store = new InMemoryTupleStore();
                seed(store, t.get("input").get("given_tuples"));
                JsonNode c = t.get("input").get("check");
                CheckResult result = store.check(
                        c.get("subject_type").asText(),
                        c.get("subject_id").asText(),
                        c.get("relation").asText(),
                        c.get("object_type").asText(),
                        c.get("object_id").asText()
                );
                JsonNode expected = t.get("expected").get("result");
                assertEquals(expected.get("allowed").asBoolean(), result.allowed());
            }));
        }
        return tests;
    }

    // ─── authorization.check_any (set form) ───

    @TestFactory
    List<DynamicTest> checkAnyConformance() throws IOException {
        JsonNode fixture = loadFixture("authorization/check-any.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode t : fixture.get("tests")) {
            String id = t.get("id").asText();
            String desc = t.get("description").asText();
            tests.add(DynamicTest.dynamicTest("[" + id + "] " + desc, () -> {
                InMemoryTupleStore store = new InMemoryTupleStore();
                seed(store, t.get("input").get("given_tuples"));
                JsonNode c = t.get("input").get("check");
                List<String> relations = new ArrayList<>();
                c.get("relations").forEach(r -> relations.add(r.asText()));
                JsonNode expected = t.get("expected");
                if (expected.has("error")) {
                    Class<? extends RuntimeException> ctor =
                            errorClassForSpecName(expected.get("error").asText());
                    assertThrows(ctor, () -> store.checkAny(
                            c.get("subject_type").asText(),
                            c.get("subject_id").asText(),
                            relations,
                            c.get("object_type").asText(),
                            c.get("object_id").asText()
                    ));
                } else {
                    CheckResult result = store.checkAny(
                            c.get("subject_type").asText(),
                            c.get("subject_id").asText(),
                            relations,
                            c.get("object_type").asText(),
                            c.get("object_id").asText()
                    );
                    assertEquals(expected.get("result").get("allowed").asBoolean(),
                            result.allowed());
                }
            }));
        }
        return tests;
    }

    // ─── authorization.create_tuple (uniqueness + format) ───

    private List<DynamicTest> createTupleConformance(String fixtureName) throws IOException {
        JsonNode fixture = loadFixture("authorization/" + fixtureName);
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode t : fixture.get("tests")) {
            String id = t.get("id").asText();
            String desc = t.get("description").asText();
            tests.add(DynamicTest.dynamicTest("[" + id + "] " + desc, () -> {
                InMemoryTupleStore store = new InMemoryTupleStore();
                seed(store, t.get("input").get("given_tuples"));
                JsonNode c = t.get("input").get("create");
                JsonNode expected = t.get("expected");
                if (expected.has("error")) {
                    Class<? extends RuntimeException> ctor =
                            errorClassForSpecName(expected.get("error").asText());
                    assertThrows(ctor, () -> store.createTuple(
                            c.get("subject_type").asText(),
                            c.get("subject_id").asText(),
                            c.get("relation").asText(),
                            c.get("object_type").asText(),
                            c.get("object_id").asText()
                    ));
                } else {
                    Tuple created = store.createTuple(
                            c.get("subject_type").asText(),
                            c.get("subject_id").asText(),
                            c.get("relation").asText(),
                            c.get("object_type").asText(),
                            c.get("object_id").asText()
                    );
                    assertTrue(created.id().startsWith("tup_"));
                }
            }));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> uniquenessConformance() throws IOException {
        return createTupleConformance("uniqueness.json");
    }

    @TestFactory
    List<DynamicTest> formatConformance() throws IOException {
        return createTupleConformance("format.json");
    }

    // ─── v0.2: rewrite-rules conformance ───
    //
    // Per ADR 0007. Each test optionally declares a `rules` field; the
    // harness instantiates the store with those rules registered before
    // running the check.

    private static Map<String, Map<String, List<RuleNode>>> parseRules(JsonNode rulesNode) {
        if (rulesNode == null || rulesNode.isNull()) return null;
        Map<String, Map<String, List<RuleNode>>> out = new HashMap<>();
        Iterator<Map.Entry<String, JsonNode>> objIt = rulesNode.fields();
        while (objIt.hasNext()) {
            Map.Entry<String, JsonNode> objEntry = objIt.next();
            Map<String, List<RuleNode>> relMap = new HashMap<>();
            Iterator<Map.Entry<String, JsonNode>> relIt = objEntry.getValue().fields();
            while (relIt.hasNext()) {
                Map.Entry<String, JsonNode> relEntry = relIt.next();
                List<RuleNode> nodes = new ArrayList<>();
                for (JsonNode n : relEntry.getValue()) {
                    nodes.add(parseRuleNode(n));
                }
                relMap.put(relEntry.getKey(), nodes);
            }
            out.put(objEntry.getKey(), relMap);
        }
        return out;
    }

    private static RuleNode parseRuleNode(JsonNode node) {
        String type = node.get("type").asText();
        return switch (type) {
            case "this" -> new ThisNode();
            case "computed_userset" -> new ComputedUserset(node.get("relation").asText());
            case "tuple_to_userset" -> new TupleToUserset(
                    node.get("tupleset_relation").asText(),
                    node.get("computed_userset_relation").asText()
            );
            default -> throw new IllegalArgumentException("Unknown rule node type: " + type);
        };
    }

    private List<DynamicTest> rewriteFixtureBlock(String fixtureName) throws IOException {
        JsonNode fixture = loadFixture("authorization/rewrite-rules/" + fixtureName);
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode t : fixture.get("tests")) {
            String id = t.get("id").asText();
            String desc = t.get("description").asText();
            tests.add(DynamicTest.dynamicTest("[" + id + "] " + desc, () -> {
                Map<String, Map<String, List<RuleNode>>> rules = parseRules(t.get("rules"));
                InMemoryTupleStore store = rules != null
                        ? InMemoryTupleStore.withRules(rules)
                        : new InMemoryTupleStore();
                seed(store, t.get("input").get("given_tuples"));
                JsonNode c = t.get("input").get("check");
                CheckResult result = store.check(
                        c.get("subject_type").asText(),
                        c.get("subject_id").asText(),
                        c.get("relation").asText(),
                        c.get("object_type").asText(),
                        c.get("object_id").asText()
                );
                JsonNode expected = t.get("expected").get("result");
                assertEquals(expected.get("allowed").asBoolean(), result.allowed());
            }));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> rewriteComputedUsersetConformance() throws IOException {
        return rewriteFixtureBlock("computed-userset.json");
    }

    @TestFactory
    List<DynamicTest> rewriteTupleToUsersetConformance() throws IOException {
        return rewriteFixtureBlock("tuple-to-userset.json");
    }

    @TestFactory
    List<DynamicTest> rewriteEmptyRulesEqualsV01Conformance() throws IOException {
        return rewriteFixtureBlock("empty-rules-equals-v01.json");
    }

    // ─── v0.3: Postgres-backed rewrite-rule conformance (ADR 0017) ───
    // Gated on AUTHZ_POSTGRES_URL — same fixture corpus, PostgresTupleStore backend.

    private static DataSource buildDataSource() {
        String url = System.getenv("AUTHZ_POSTGRES_URL");
        URI uri = URI.create(url.replaceFirst("^postgresql:", "http:"));
        PGSimpleDataSource ds = new PGSimpleDataSource();
        ds.setServerNames(new String[]{ uri.getHost() });
        ds.setPortNumbers(new int[]{ uri.getPort() > 0 ? uri.getPort() : 5432 });
        String path = uri.getPath();
        ds.setDatabaseName(path != null && path.length() > 1 ? path.substring(1) : "postgres");
        if (uri.getUserInfo() != null) {
            String[] ui = uri.getUserInfo().split(":", 2);
            ds.setUser(ui[0]);
            if (ui.length > 1) ds.setPassword(ui[1]);
        }
        return ds;
    }

    private List<DynamicTest> rewriteFixtureBlockPostgres(String fixtureName) throws IOException, SQLException {
        DataSource ds = buildDataSource();
        String testSchemaSql;
        try (InputStream in = ConformanceTest.class.getResourceAsStream("/authz-test-schema.sql")) {
            testSchemaSql = new String(in.readAllBytes());
        }
        // Apply schema once before any test runs — idempotent (DROP TABLE IF EXISTS tup CASCADE)
        try (Connection conn = ds.getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute(testSchemaSql);
        }
        JsonNode fixture = loadFixture("authorization/rewrite-rules/" + fixtureName);
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode t : fixture.get("tests")) {
            String id = t.get("id").asText();
            String desc = t.get("description").asText();
            tests.add(DynamicTest.dynamicTest("[postgres][" + id + "] " + desc, () -> {
                // Isolate data per test case
                try (Connection conn = ds.getConnection(); Statement stmt = conn.createStatement()) {
                    stmt.execute("TRUNCATE tup");
                }
                Map<String, Map<String, List<RuleNode>>> rules = parseRules(t.get("rules"));
                PostgresTupleStore store = rules != null
                        ? new PostgresTupleStore(ds, rules)
                        : new PostgresTupleStore(ds);
                seed(store, t.get("input").get("given_tuples"));
                JsonNode c = t.get("input").get("check");
                CheckResult result = store.check(
                        c.get("subject_type").asText(),
                        c.get("subject_id").asText(),
                        c.get("relation").asText(),
                        c.get("object_type").asText(),
                        c.get("object_id").asText()
                );
                JsonNode expected = t.get("expected").get("result");
                assertEquals(expected.get("allowed").asBoolean(), result.allowed());
            }));
        }
        return tests;
    }

    @TestFactory
    @EnabledIfEnvironmentVariable(named = "AUTHZ_POSTGRES_URL", matches = ".+")
    List<DynamicTest> rewriteComputedUsersetPostgresConformance() throws IOException, SQLException {
        return rewriteFixtureBlockPostgres("computed-userset.json");
    }

    @TestFactory
    @EnabledIfEnvironmentVariable(named = "AUTHZ_POSTGRES_URL", matches = ".+")
    List<DynamicTest> rewriteTupleToUsersetPostgresConformance() throws IOException, SQLException {
        return rewriteFixtureBlockPostgres("tuple-to-userset.json");
    }

    @TestFactory
    @EnabledIfEnvironmentVariable(named = "AUTHZ_POSTGRES_URL", matches = ".+")
    List<DynamicTest> rewriteEmptyRulesEqualsV01PostgresConformance() throws IOException, SQLException {
        return rewriteFixtureBlockPostgres("empty-rules-equals-v01.json");
    }
}
