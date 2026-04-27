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
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnabledIfEnvironmentVariable(named = "AUTHZ_POSTGRES_URL", matches = ".+")
class PostgresShareStoreTest {

    private static DataSource dataSource;
    private static String schemaSql;

    private PostgresShareStore store;
    private String alice;
    private String project42;

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
        store = new PostgresShareStore(dataSource);
        alice = registerUser();
        project42 = UUID.randomUUID().toString();
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

    @Test
    void createShare_freshIdAndDistinctToken() {
        CreateShareResult r = store.createShare("proj", project42, "viewer", alice, 600);
        assertTrue(r.share().id().matches("^shr_[0-9a-f]{32}$"));
        assertNotEquals(r.token(), r.share().id());
        assertFalse(r.share().singleUse());
        assertNull(r.share().consumedAt());
    }

    @Test
    void rejectMalformedRelation() {
        assertThrows(InvalidFormatError.class, () ->
                store.createShare("proj", project42, "Viewer!", alice, 600));
    }

    @Test
    void rejectTtlAboveCeiling() {
        assertThrows(InvalidFormatError.class, () ->
                store.createShare("proj", project42, "viewer", alice, ShareStore.MAX_TTL_SECONDS + 1));
    }

    @Test
    void verifyShareToken_roundTrips() {
        CreateShareResult r = store.createShare("proj", project42, "viewer", alice, 600);
        VerifiedShare v = store.verifyShareToken(r.token());
        assertEquals(r.share().id(), v.shareId());
        assertEquals("proj", v.objectType());
        assertEquals(project42, v.objectId());
        assertEquals("viewer", v.relation());
    }

    @Test
    void verifyJunkRaises() {
        assertThrows(InvalidShareTokenError.class, () -> store.verifyShareToken("not-a-real-token"));
    }

    @Test
    void verifyRevokedRaises() {
        CreateShareResult r = store.createShare("proj", project42, "viewer", alice, 600);
        store.revokeShare(r.share().id());
        assertThrows(ShareRevokedError.class, () -> store.verifyShareToken(r.token()));
    }

    @Test
    void verifyExpiredRaises() {
        AtomicReference<Instant> nowRef = new AtomicReference<>(Instant.parse("2026-04-27T00:00:00Z"));
        Clock clock = new Clock() {
            @Override
            public ZoneId getZone() { return ZoneId.of("UTC"); }
            @Override
            public Clock withZone(ZoneId zone) { return this; }
            @Override
            public Instant instant() { return nowRef.get(); }
        };
        PostgresShareStore s = new PostgresShareStore(dataSource, clock);
        CreateShareResult r = s.createShare("proj", project42, "viewer", alice, 60);
        nowRef.set(nowRef.get().plus(Duration.ofSeconds(61)));
        assertThrows(ShareExpiredError.class, () -> s.verifyShareToken(r.token()));
    }

    @Test
    void singleUse_consumesOnFirstVerify() {
        CreateShareResult r = store.createShare("proj", project42, "viewer", alice, 600, true);
        store.verifyShareToken(r.token());
        Share consumed = store.getShare(r.share().id());
        assertNotNull(consumed.consumedAt());
        assertThrows(ShareConsumedError.class, () -> store.verifyShareToken(r.token()));
    }

    @Test
    void nonSingleUse_canVerifyRepeatedly() {
        CreateShareResult r = store.createShare("proj", project42, "viewer", alice, 600);
        store.verifyShareToken(r.token());
        VerifiedShare second = store.verifyShareToken(r.token());
        assertEquals("viewer", second.relation());
    }

    @Test
    void revokedPlusExpired_yieldsRevoked() {
        AtomicReference<Instant> nowRef = new AtomicReference<>(Instant.parse("2026-04-27T00:00:00Z"));
        Clock clock = new Clock() {
            @Override
            public ZoneId getZone() { return ZoneId.of("UTC"); }
            @Override
            public Clock withZone(ZoneId zone) { return this; }
            @Override
            public Instant instant() { return nowRef.get(); }
        };
        PostgresShareStore s = new PostgresShareStore(dataSource, clock);
        CreateShareResult r = s.createShare("proj", project42, "viewer", alice, 60);
        s.revokeShare(r.share().id());
        nowRef.set(nowRef.get().plus(Duration.ofSeconds(61)));
        assertThrows(ShareRevokedError.class, () -> s.verifyShareToken(r.token()));
    }

    @Test
    void revokeShare_idempotent() {
        CreateShareResult r = store.createShare("proj", project42, "viewer", alice, 600);
        Share first = store.revokeShare(r.share().id());
        Share second = store.revokeShare(r.share().id());
        assertEquals(first.revokedAt(), second.revokedAt());
    }

    @Test
    void revokeUnknown_raises() {
        assertThrows(ShareNotFoundError.class, () -> store.revokeShare(Id.generate("shr")));
    }

    @Test
    void getUnknown_raises() {
        assertThrows(ShareNotFoundError.class, () -> store.getShare(Id.generate("shr")));
    }

    // ─── ADR 0012: created_by must be an active user ───

    @Test
    void rejectsCreateWhenCreatorIsSuspended() throws Exception {
        try (Connection conn = dataSource.getConnection();
             var ps = conn.prepareStatement(
                     "UPDATE usr SET status = 'suspended' WHERE id = ?")) {
            ps.setObject(1, UUID.fromString(Id.decode(alice).uuid()));
            ps.executeUpdate();
        }
        assertThrows(PreconditionError.class, () ->
                store.createShare("proj", project42, "viewer", alice, 600));
    }

    @Test
    void rejectsCreateWhenCreatorIsRevoked() throws Exception {
        try (Connection conn = dataSource.getConnection();
             var ps = conn.prepareStatement(
                     "UPDATE usr SET status = 'revoked' WHERE id = ?")) {
            ps.setObject(1, UUID.fromString(Id.decode(alice).uuid()));
            ps.executeUpdate();
        }
        assertThrows(PreconditionError.class, () ->
                store.createShare("proj", project42, "viewer", alice, 600));
    }

    @Test
    void rejectsCreateWhenCreatorDoesNotExist() {
        String ghost = Id.generate("usr");
        assertThrows(PreconditionError.class, () ->
                store.createShare("proj", project42, "viewer", ghost, 600));
    }

    @Test
    void consumedPlusExpired_yieldsConsumed() {
        // Spec error precedence: consumed > expired.
        AtomicReference<Instant> nowRef = new AtomicReference<>(Instant.parse("2026-04-27T00:00:00Z"));
        Clock clock = new Clock() {
            @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return nowRef.get(); }
        };
        PostgresShareStore s = new PostgresShareStore(dataSource, clock);
        CreateShareResult r = s.createShare("proj", project42, "viewer", alice, 60, true);
        s.verifyShareToken(r.token()); // consumes
        nowRef.set(nowRef.get().plus(Duration.ofSeconds(61))); // now also expired
        assertThrows(ShareConsumedError.class, () -> s.verifyShareToken(r.token()));
    }

    @Test
    void createdBy_roundTrips() {
        CreateShareResult r = store.createShare("proj", project42, "viewer", alice, 600);
        Share fetched = store.getShare(r.share().id());
        assertEquals(alice, fetched.createdBy());
        assertTrue(fetched.createdBy().startsWith("usr_"));
    }

    @Test
    void list_includesRevokedAndConsumed() {
        CreateShareResult active = store.createShare("proj", project42, "viewer", alice, 600);
        CreateShareResult revoked = store.createShare("proj", project42, "viewer", alice, 600);
        CreateShareResult consumed = store.createShare("proj", project42, "viewer", alice, 600, true);
        store.revokeShare(revoked.share().id());
        store.verifyShareToken(consumed.token());
        Page<Share> page = store.listSharesForObject("proj", project42, null, 50);
        Set<String> ids = new HashSet<>();
        page.data().forEach(s -> ids.add(s.id()));
        assertTrue(ids.contains(active.share().id()));
        assertTrue(ids.contains(revoked.share().id()));
        assertTrue(ids.contains(consumed.share().id()));
    }

    @Test
    void listSharesForObject_paginates() {
        String other = UUID.randomUUID().toString();
        for (String obj : new String[]{project42, project42, other, project42}) {
            store.createShare("proj", obj, "viewer", alice, 600);
        }
        Page<Share> page1 = store.listSharesForObject("proj", project42, null, 2);
        assertEquals(2, page1.data().size());
        assertNotNull(page1.nextCursor());
        Page<Share> page2 = store.listSharesForObject("proj", project42, page1.nextCursor(), 10);
        Set<String> ids = new HashSet<>();
        page1.data().forEach(s -> ids.add(s.id()));
        page2.data().forEach(s -> ids.add(s.id()));
        assertEquals(3, ids.size());
    }
}
