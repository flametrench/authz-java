// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import dev.flametrench.ids.Id;

import javax.sql.DataSource;
import java.sql.Array;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * PostgresTupleStore — Postgres-backed implementation of TupleStore.
 *
 * <p>Mirrors {@link InMemoryTupleStore} byte-for-byte at the SDK
 * boundary; the difference is durability and concurrency. Schema lives
 * in {@code spec/reference/postgres.sql} (the {@code tup} table).
 *
 * <p>Design notes:
 * <ul>
 *   <li>All ID columns store native UUID. Wire-format prefixed IDs are
 *       computed at the SDK boundary via {@link Id}.</li>
 *   <li>The natural-key UNIQUE constraint
 *       {@code (subject_type, subject_id, relation, object_type, object_id)}
 *       drives duplicate detection.</li>
 *   <li>{@code check} / {@code checkAny} are exact-match only here in
 *       v0.2. Rewrite-rule support (ADR 0007) requires the in-memory
 *       store with the {@code rules} constructor option; bridging the
 *       evaluator to JDBC I/O is tracked for v0.3.</li>
 * </ul>
 *
 * <p>Connection handling: callers pass a {@link DataSource}. Each
 * operation borrows a connection for the duration of its work and
 * returns it. Multi-statement ops (none in authz, but inherited
 * pattern) would run inside an explicit transaction.
 */
public class PostgresTupleStore implements TupleStore {

    private static final String UNIQUE_VIOLATION = "23505";

    private static final String TUP_COLS =
            "id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by";

    private final DataSource dataSource;
    private final Clock clock;

    public PostgresTupleStore(DataSource dataSource) {
        this(dataSource, Clock.systemUTC());
    }

    public PostgresTupleStore(DataSource dataSource, Clock clock) {
        this.dataSource = dataSource;
        this.clock = clock;
    }

    private static String wireToUuid(String wireId) {
        return Id.decode(wireId).uuid();
    }

    /**
     * The {@code tup.object_id} column is typed UUID in the spec
     * schema. Adopters' application object types use bare-UUID
     * identifiers (e.g. {@code "0190..."}) at the SDK boundary; the
     * Postgres JDBC driver doesn't auto-cast strings to UUID, so
     * convert at the boundary.
     */
    private static UUID objectIdToUuid(String objectId) {
        // Accept both hyphenated ("0190f2a8-...") and 32-char hex forms.
        if (objectId.length() == 32) {
            String s = objectId;
            String formatted = s.substring(0, 8) + "-" + s.substring(8, 12)
                    + "-" + s.substring(12, 16) + "-" + s.substring(16, 20)
                    + "-" + s.substring(20);
            return UUID.fromString(formatted);
        }
        return UUID.fromString(objectId);
    }

    private Instant now() {
        return clock.instant();
    }

    private static void validate(String relation, String objectType) {
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
    }

    private static boolean isUniqueViolation(SQLException e) {
        return UNIQUE_VIOLATION.equals(e.getSQLState());
    }

    private static Tuple rowToTuple(ResultSet rs) throws SQLException {
        String tupUuid = rs.getString("id");
        String subjectUuid = rs.getString("subject_id");
        String createdByUuid = rs.getString("created_by");
        return new Tuple(
                Id.encode("tup", tupUuid),
                rs.getString("subject_type"),
                Id.encode("usr", subjectUuid),
                rs.getString("relation"),
                rs.getString("object_type"),
                rs.getString("object_id"),
                rs.getTimestamp("created_at").toInstant(),
                createdByUuid != null ? Id.encode("usr", createdByUuid) : null
        );
    }

    // ─── Mutations ───

    @Override
    public Tuple createTuple(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId,
            String createdBy
    ) {
        validate(relation, objectType);
        UUID tupUuid = UUID.fromString(Id.decode(Id.generate("tup")).uuid());
        UUID subjectUuid = UUID.fromString(wireToUuid(subjectId));
        UUID createdByUuid = createdBy != null ? UUID.fromString(wireToUuid(createdBy)) : null;
        Instant now = now();
        try (Connection conn = dataSource.getConnection()) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)"
                  + " VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING " + TUP_COLS)) {
                ps.setObject(1, tupUuid);
                ps.setString(2, subjectType);
                ps.setObject(3, subjectUuid);
                ps.setString(4, relation);
                ps.setString(5, objectType);
                ps.setObject(6, objectIdToUuid(objectId));
                ps.setTimestamp(7, Timestamp.from(now));
                ps.setObject(8, createdByUuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        throw new SQLException("INSERT returned no row");
                    }
                    return rowToTuple(rs);
                }
            }
        } catch (SQLException e) {
            if (isUniqueViolation(e)) {
                String existing = lookupExistingTupleId(subjectType, subjectUuid, relation, objectType, objectId);
                if (existing != null) {
                    throw new DuplicateTupleError(
                            "Tuple with identical natural key already exists",
                            Id.encode("tup", existing)
                    );
                }
            }
            throw new RuntimeException(e);
        }
    }

    private String lookupExistingTupleId(
            String subjectType,
            UUID subjectUuid,
            String relation,
            String objectType,
            String objectId
    ) {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT id FROM tup WHERE subject_type = ? AND subject_id = ? AND relation = ?"
                   + " AND object_type = ? AND object_id = ?")) {
            ps.setString(1, subjectType);
            ps.setObject(2, subjectUuid);
            ps.setString(3, relation);
            ps.setString(4, objectType);
            ps.setObject(5, objectIdToUuid(objectId));
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString("id") : null;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void deleteTuple(String tupleId) {
        UUID uuid = UUID.fromString(wireToUuid(tupleId));
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement("DELETE FROM tup WHERE id = ?")) {
            ps.setObject(1, uuid);
            int affected = ps.executeUpdate();
            if (affected == 0) {
                throw new TupleNotFoundError("Tuple " + tupleId + " not found");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int cascadeRevokeSubject(String subjectType, String subjectId) {
        UUID subjectUuid = UUID.fromString(wireToUuid(subjectId));
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "DELETE FROM tup WHERE subject_type = ? AND subject_id = ?")) {
            ps.setString(1, subjectType);
            ps.setObject(2, subjectUuid);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    // ─── check / checkAny ───

    @Override
    public CheckResult check(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId
    ) {
        return checkAny(subjectType, subjectId, List.of(relation), objectType, objectId);
    }

    @Override
    public CheckResult checkAny(
            String subjectType,
            String subjectId,
            List<String> relations,
            String objectType,
            String objectId
    ) {
        if (relations == null || relations.isEmpty()) {
            throw new EmptyRelationSetError();
        }
        UUID subjectUuid = UUID.fromString(wireToUuid(subjectId));
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT id FROM tup WHERE subject_type = ? AND subject_id = ?"
                   + " AND relation = ANY(?) AND object_type = ? AND object_id = ? LIMIT 1")) {
            Array relArray = conn.createArrayOf("text", relations.toArray(new String[0]));
            ps.setString(1, subjectType);
            ps.setObject(2, subjectUuid);
            ps.setArray(3, relArray);
            ps.setString(4, objectType);
            ps.setObject(5, objectIdToUuid(objectId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return CheckResult.denied();
                }
                return CheckResult.allowed(Id.encode("tup", rs.getString("id")));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    // ─── Read accessors ───

    @Override
    public Tuple getTuple(String tupleId) {
        UUID uuid = UUID.fromString(wireToUuid(tupleId));
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT " + TUP_COLS + " FROM tup WHERE id = ?")) {
            ps.setObject(1, uuid);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    throw new TupleNotFoundError("Tuple " + tupleId + " not found");
                }
                return rowToTuple(rs);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Page<Tuple> listTuplesBySubject(
            String subjectType,
            String subjectId,
            String cursor,
            int limit
    ) {
        int cap = Math.min(limit, 200);
        StringBuilder sql = new StringBuilder(
                "SELECT " + TUP_COLS + " FROM tup WHERE subject_type = ? AND subject_id = ?"
        );
        if (cursor != null) {
            sql.append(" AND id > ?");
        }
        sql.append(" ORDER BY id LIMIT ?");
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql.toString())) {
            int idx = 1;
            ps.setString(idx++, subjectType);
            ps.setObject(idx++, UUID.fromString(wireToUuid(subjectId)));
            if (cursor != null) {
                ps.setObject(idx++, UUID.fromString(wireToUuid(cursor)));
            }
            ps.setInt(idx, cap + 1);
            try (ResultSet rs = ps.executeQuery()) {
                return paginate(rs, cap);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Page<Tuple> listTuplesByObject(
            String objectType,
            String objectId,
            String relation,
            String cursor,
            int limit
    ) {
        int cap = Math.min(limit, 200);
        StringBuilder sql = new StringBuilder(
                "SELECT " + TUP_COLS + " FROM tup WHERE object_type = ? AND object_id = ?"
        );
        if (relation != null) sql.append(" AND relation = ?");
        if (cursor != null) sql.append(" AND id > ?");
        sql.append(" ORDER BY id LIMIT ?");
        try (Connection conn = dataSource.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql.toString())) {
            int idx = 1;
            ps.setString(idx++, objectType);
            ps.setObject(idx++, objectIdToUuid(objectId));
            if (relation != null) ps.setString(idx++, relation);
            if (cursor != null) ps.setObject(idx++, UUID.fromString(wireToUuid(cursor)));
            ps.setInt(idx, cap + 1);
            try (ResultSet rs = ps.executeQuery()) {
                return paginate(rs, cap);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    private static Page<Tuple> paginate(ResultSet rs, int cap) throws SQLException {
        List<Tuple> rows = new ArrayList<>();
        while (rs.next()) {
            rows.add(rowToTuple(rs));
        }
        boolean hasMore = rows.size() > cap;
        List<Tuple> data = hasMore ? rows.subList(0, cap) : rows;
        String nextCursor = hasMore && !data.isEmpty() ? data.get(data.size() - 1).id() : null;
        return new Page<>(List.copyOf(data), nextCursor);
    }
}
