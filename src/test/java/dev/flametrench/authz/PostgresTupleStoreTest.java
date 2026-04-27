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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for {@link PostgresTupleStore}.
 *
 * <p>Gated on the {@code AUTHZ_POSTGRES_URL} environment variable —
 * skipped entirely when unset, mirroring the Node and Python suites.
 */
@EnabledIfEnvironmentVariable(named = "AUTHZ_POSTGRES_URL", matches = ".+")
class PostgresTupleStoreTest {

    private static DataSource dataSource;
    private static String schemaSql;

    private PostgresTupleStore store;
    private String alice;
    private String bob;
    private String carol;

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
        schemaSql = Files.readString(
                Path.of("src/test/resources/postgres-schema.sql")
        );
    }

    @BeforeEach
    void resetSchema() throws Exception {
        try (Connection conn = dataSource.getConnection();
             Statement st = conn.createStatement()) {
            st.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;");
            st.execute(schemaSql);
        }
        store = new PostgresTupleStore(dataSource);
        alice = registerUser();
        bob = registerUser();
        carol = registerUser();
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

    private static String newObjectId() {
        return Id.decode(Id.generate("usr")).uuid();
    }

    @Test
    void createTuple_yieldsFreshId() {
        String project = newObjectId();
        Tuple t = store.createTuple("usr", alice, "owner", "proj", project, alice);
        assertTrue(t.id().matches("^tup_[0-9a-f]{32}$"));
        assertEquals(alice, t.subjectId());
        assertEquals(alice, t.createdBy());
        assertEquals(project, t.objectId());
    }

    @Test
    void duplicateNaturalKey_raises() {
        String project = newObjectId();
        Tuple first = store.createTuple("usr", alice, "viewer", "proj", project);
        DuplicateTupleError err = assertThrows(
                DuplicateTupleError.class,
                () -> store.createTuple("usr", alice, "viewer", "proj", project)
        );
        assertEquals(first.id(), err.getExistingTupleId());
    }

    @Test
    void malformedRelation_rejected() {
        assertThrows(InvalidFormatError.class, () ->
                store.createTuple("usr", alice, "Owner!", "proj", newObjectId()));
    }

    @Test
    void malformedObjectType_rejected() {
        assertThrows(InvalidFormatError.class, () ->
                store.createTuple("usr", alice, "owner", "Project", newObjectId()));
    }

    @Test
    void check_returnsMatch() {
        String project = newObjectId();
        Tuple t = store.createTuple("usr", alice, "editor", "proj", project);
        CheckResult r = store.check("usr", alice, "editor", "proj", project);
        assertTrue(r.allowed());
        assertEquals(t.id(), r.matchedTupleId());
    }

    @Test
    void check_returnsFalseWhenNoMatch() {
        CheckResult r = store.check("usr", alice, "owner", "proj", newObjectId());
        assertFalse(r.allowed());
        assertNull(r.matchedTupleId());
    }

    @Test
    void checkAny_matchesAnySupplied() {
        String project = newObjectId();
        store.createTuple("usr", alice, "editor", "proj", project);
        CheckResult r = store.checkAny("usr", alice, List.of("viewer", "editor", "owner"), "proj", project);
        assertTrue(r.allowed());
    }

    @Test
    void checkAny_rejectsEmptyRelations() {
        assertThrows(EmptyRelationSetError.class, () ->
                store.checkAny("usr", alice, List.of(), "proj", newObjectId()));
    }

    @Test
    void deleteTuple_thenCheckIsFalse() {
        String project = newObjectId();
        Tuple t = store.createTuple("usr", alice, "editor", "proj", project);
        store.deleteTuple(t.id());
        CheckResult r = store.check("usr", alice, "editor", "proj", project);
        assertFalse(r.allowed());
    }

    @Test
    void deleteUnknownTuple_raises() {
        assertThrows(TupleNotFoundError.class, () ->
                store.deleteTuple(Id.generate("tup")));
    }

    @Test
    void cascadeRevokeSubject_deletesAll() {
        String p1 = newObjectId();
        String p2 = newObjectId();
        store.createTuple("usr", alice, "editor", "proj", p1);
        store.createTuple("usr", alice, "viewer", "proj", p2);
        store.createTuple("usr", bob, "viewer", "proj", p1);
        int removed = store.cascadeRevokeSubject("usr", alice);
        assertEquals(2, removed);
        assertTrue(store.listTuplesBySubject("usr", alice, null, 50).data().isEmpty());
        assertEquals(1, store.listTuplesBySubject("usr", bob, null, 50).data().size());
    }

    @Test
    void getTuple_roundTrips() {
        String project = newObjectId();
        Tuple t = store.createTuple("usr", alice, "owner", "proj", project, alice);
        Tuple f = store.getTuple(t.id());
        assertEquals(t.id(), f.id());
        assertEquals(alice, f.subjectId());
        assertEquals("owner", f.relation());
        assertEquals(project, f.objectId());
        assertEquals(alice, f.createdBy());
    }

    @Test
    void getTuple_unknown_raises() {
        assertThrows(TupleNotFoundError.class, () ->
                store.getTuple(Id.generate("tup")));
    }

    @Test
    void listTuplesByObject_filtersByRelation() {
        String p42 = newObjectId();
        String p99 = newObjectId();
        store.createTuple("usr", alice, "owner", "proj", p42);
        store.createTuple("usr", bob, "viewer", "proj", p42);
        store.createTuple("usr", carol, "viewer", "proj", p99);
        Page<Tuple> allOnP42 = store.listTuplesByObject("proj", p42, null, null, 50);
        assertEquals(2, allOnP42.data().size());
        Page<Tuple> viewers = store.listTuplesByObject("proj", p42, "viewer", null, 50);
        assertEquals(1, viewers.data().size());
        assertEquals(bob, viewers.data().get(0).subjectId());
    }

    @Test
    void listTuplesBySubject_paginates() {
        for (int i = 0; i < 5; i++) {
            store.createTuple("usr", alice, "viewer", "proj", newObjectId());
        }
        Page<Tuple> page1 = store.listTuplesBySubject("usr", alice, null, 2);
        assertEquals(2, page1.data().size());
        assertNotNull(page1.nextCursor());
        Page<Tuple> page2 = store.listTuplesBySubject("usr", alice, page1.nextCursor(), 10);
        Set<String> all = new HashSet<>();
        page1.data().forEach(t -> all.add(t.id()));
        page2.data().forEach(t -> all.add(t.id()));
        assertEquals(5, all.size());
    }
}
