// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import dev.flametrench.ids.Id;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Postgres-backed ShareStore. Mirrors {@link InMemoryShareStore}
 * byte-for-byte at the SDK boundary.
 *
 * <p>Verification is one round-trip on the lookup index
 * {@code shr_token_hash_idx}. Single-use consumption uses
 * {@code UPDATE … WHERE consumed_at IS NULL RETURNING …} so concurrent
 * verifies of a single-use token race-correctly to exactly one success.
 */
public class PostgresShareStore implements ShareStore {

    private static final String SHR_COLS =
            "id, token_hash, object_type, object_id, relation, created_by, "
            + "expires_at, single_use, consumed_at, revoked_at, created_at";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final DataSource dataSource;
    private final Clock clock;

    public PostgresShareStore(DataSource dataSource) {
        this(dataSource, Clock.systemUTC());
    }

    public PostgresShareStore(DataSource dataSource, Clock clock) {
        this.dataSource = dataSource;
        this.clock = clock;
    }

    private Instant now() {
        return clock.instant();
    }

    private static UUID wireToUuid(String wireId) {
        return UUID.fromString(Id.decode(wireId).uuid());
    }

    private static byte[] hashTokenBytes(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(token.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String generateToken() {
        byte[] raw = new byte[32];
        SECURE_RANDOM.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static Share rowToShare(ResultSet rs) throws SQLException {
        Timestamp consumedAt = rs.getTimestamp("consumed_at");
        Timestamp revokedAt = rs.getTimestamp("revoked_at");
        return new Share(
                Id.encode("shr", rs.getString("id")),
                rs.getString("object_type"),
                rs.getString("object_id"),
                rs.getString("relation"),
                Id.encode("usr", rs.getString("created_by")),
                rs.getTimestamp("expires_at").toInstant(),
                rs.getBoolean("single_use"),
                consumedAt != null ? consumedAt.toInstant() : null,
                revokedAt != null ? revokedAt.toInstant() : null,
                rs.getTimestamp("created_at").toInstant()
        );
    }

    private static void validate(String relation, String objectType, long expiresInSeconds) {
        if (!Patterns.RELATION_NAME.matcher(relation).matches()) {
            throw new InvalidFormatError(
                    "relation '" + relation + "' must match " + Patterns.RELATION_NAME.pattern(),
                    "relation"
            );
        }
        if (!Patterns.TYPE_PREFIX.matcher(objectType).matches()) {
            throw new InvalidFormatError(
                    "objectType '" + objectType + "' must match " + Patterns.TYPE_PREFIX.pattern(),
                    "object_type"
            );
        }
        if (expiresInSeconds <= 0) {
            throw new InvalidFormatError(
                    "expiresInSeconds must be positive, got " + expiresInSeconds,
                    "expires_in_seconds"
            );
        }
        if (expiresInSeconds > MAX_TTL_SECONDS) {
            throw new InvalidFormatError(
                    "expiresInSeconds exceeds the spec ceiling of "
                  + MAX_TTL_SECONDS + " (365 days)",
                    "expires_in_seconds"
            );
        }
    }

    private static final java.util.regex.Pattern OBJECT_ID_WIRE =
            java.util.regex.Pattern.compile("^[a-z]{2,6}_[0-9a-f]{32}$");

    /**
     * Decode an {@code object_id} to a Postgres-bindable UUID. See
     * {@code PostgresTupleStore#objectIdToUuid} for rationale (spec#8) —
     * wire-format prefixed IDs with non-registered prefixes (e.g.
     * {@code proj_<hex>}) are decoded via {@link Id#decodeAny(String)}.
     */
    private static UUID objectIdToUuid(String objectId) {
        if (OBJECT_ID_WIRE.matcher(objectId).matches()) {
            return UUID.fromString(Id.decodeAny(objectId).uuid());
        }
        if (objectId.length() == 32) {
            String s = objectId;
            return UUID.fromString(
                    s.substring(0, 8) + "-" + s.substring(8, 12)
                  + "-" + s.substring(12, 16) + "-" + s.substring(16, 20)
                  + "-" + s.substring(20)
            );
        }
        return UUID.fromString(objectId);
    }

    @Override
    public CreateShareResult createShare(
            String objectType,
            String objectId,
            String relation,
            String createdBy,
            long expiresInSeconds,
            boolean singleUse
    ) {
        validate(relation, objectType, expiresInSeconds);
        UUID createdByUuid = wireToUuid(createdBy);
        UUID shareUuid = UUID.fromString(Id.decode(Id.generate("shr")).uuid());
        String token = generateToken();
        byte[] tokenHash = hashTokenBytes(token);
        Instant now = now();
        Instant expiresAt = now.plusSeconds(expiresInSeconds);
        try (Connection conn = dataSource.getConnection()) {
            // ADR 0012: created_by MUST resolve to an active user. The
            // DDL FK enforces existence; status is checked here at the
            // SDK layer. Suspended/revoked users with leaked credentials
            // cannot mint shares.
            try (PreparedStatement check = conn.prepareStatement(
                    "SELECT status FROM usr WHERE id = ?")) {
                check.setObject(1, createdByUuid);
                try (ResultSet rs = check.executeQuery()) {
                    if (!rs.next()) {
                        throw new PreconditionError(
                                "created_by " + createdBy + " does not exist",
                                "creator_not_found"
                        );
                    }
                    String status = rs.getString("status");
                    if (!"active".equals(status)) {
                        throw new PreconditionError(
                                "created_by " + createdBy + " is " + status
                              + "; only active users can mint shares",
                                "creator_not_active"
                        );
                    }
                }
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO shr (id, token_hash, object_type, object_id, relation,"
                  + " created_by, expires_at, single_use, created_at)"
                  + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                  + " RETURNING " + SHR_COLS)) {
                ps.setObject(1, shareUuid);
                ps.setBytes(2, tokenHash);
                ps.setString(3, objectType);
                ps.setObject(4, objectIdToUuid(objectId));
                ps.setString(5, relation);
                ps.setObject(6, createdByUuid);
                ps.setTimestamp(7, Timestamp.from(expiresAt));
                ps.setBoolean(8, singleUse);
                ps.setTimestamp(9, Timestamp.from(now));
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    return new CreateShareResult(rowToShare(rs), token);
                }
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Share getShare(String shareId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT " + SHR_COLS + " FROM shr WHERE id = ?")) {
            ps.setObject(1, wireToUuid(shareId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    throw new ShareNotFoundError("Share " + shareId + " not found");
                }
                return rowToShare(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public VerifiedShare verifyShareToken(String token) {
        byte[] inputHash = hashTokenBytes(token);
        try (Connection conn = dataSource.getConnection()) {
            boolean prevAuto = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try {
                String rowId;
                byte[] storedHash;
                Instant expiresAt;
                Timestamp consumedAt;
                Timestamp revokedAt;
                boolean singleUse;
                String objectType;
                String objectId;
                String relation;
                try (PreparedStatement ps = conn.prepareStatement(
                        "SELECT " + SHR_COLS + " FROM shr"
                      + " WHERE token_hash = ?"
                      + " ORDER BY created_at DESC LIMIT 1"
                      + " FOR UPDATE")) {
                    ps.setBytes(1, inputHash);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) throw new InvalidShareTokenError();
                        rowId = rs.getString("id");
                        storedHash = rs.getBytes("token_hash");
                        expiresAt = rs.getTimestamp("expires_at").toInstant();
                        consumedAt = rs.getTimestamp("consumed_at");
                        revokedAt = rs.getTimestamp("revoked_at");
                        singleUse = rs.getBoolean("single_use");
                        objectType = rs.getString("object_type");
                        objectId = rs.getString("object_id");
                        relation = rs.getString("relation");
                    }
                }
                // Defense-in-depth: constant-time compare on the BYTEA column.
                if (!constantTimeEquals(inputHash, storedHash)) {
                    throw new InvalidShareTokenError();
                }
                // Spec error precedence: revoked > consumed > expired.
                if (revokedAt != null) throw new ShareRevokedError();
                if (singleUse && consumedAt != null) throw new ShareConsumedError();
                Instant now = now();
                if (!now.isBefore(expiresAt)) throw new ShareExpiredError();
                if (singleUse) {
                    // Atomic consume — concurrent verifies race here. The
                    // WHERE consumed_at IS NULL is what makes the second loser.
                    try (PreparedStatement upd = conn.prepareStatement(
                            "UPDATE shr SET consumed_at = ?"
                          + " WHERE id = ? AND consumed_at IS NULL"
                          + " RETURNING id")) {
                        upd.setTimestamp(1, Timestamp.from(now));
                        upd.setObject(2, UUID.fromString(rowId));
                        try (ResultSet urs = upd.executeQuery()) {
                            if (!urs.next()) throw new ShareConsumedError();
                        }
                    }
                }
                conn.commit();
                return new VerifiedShare(
                        Id.encode("shr", rowId),
                        objectType, objectId, relation
                );
            } catch (RuntimeException | SQLException e) {
                try {
                    conn.rollback();
                } catch (SQLException ignored) {
                }
                if (e instanceof SQLException) throw new RuntimeException(e);
                throw (RuntimeException) e;
            } finally {
                conn.setAutoCommit(prevAuto);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Share revokeShare(String shareId) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "UPDATE shr SET revoked_at = COALESCE(revoked_at, ?)"
                   + " WHERE id = ?"
                   + " RETURNING " + SHR_COLS)) {
            ps.setTimestamp(1, Timestamp.from(now()));
            ps.setObject(2, wireToUuid(shareId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    throw new ShareNotFoundError("Share " + shareId + " not found");
                }
                return rowToShare(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Page<Share> listSharesForObject(
            String objectType,
            String objectId,
            String cursor,
            int limit
    ) {
        int cap = Math.min(limit, 200);
        StringBuilder sql = new StringBuilder(
                "SELECT " + SHR_COLS + " FROM shr WHERE object_type = ? AND object_id = ?"
        );
        if (cursor != null) sql.append(" AND id > ?");
        sql.append(" ORDER BY id LIMIT ?");
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql.toString())) {
            int idx = 1;
            ps.setString(idx++, objectType);
            ps.setObject(idx++, objectIdToUuid(objectId));
            if (cursor != null) ps.setObject(idx++, wireToUuid(cursor));
            ps.setInt(idx, cap + 1);
            try (ResultSet rs = ps.executeQuery()) {
                List<Share> rows = new ArrayList<>();
                while (rs.next()) rows.add(rowToShare(rs));
                boolean hasMore = rows.size() > cap;
                List<Share> data = hasMore ? rows.subList(0, cap) : rows;
                String nextCursor = hasMore && !data.isEmpty()
                        ? data.get(data.size() - 1).id() : null;
                return new Page<>(List.copyOf(data), nextCursor);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
