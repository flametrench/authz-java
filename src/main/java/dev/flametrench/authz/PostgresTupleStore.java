// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import dev.flametrench.ids.Id;

import javax.sql.DataSource;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
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
import java.util.Map;
import java.util.UUID;

/**
 * PostgresTupleStore — Postgres-backed implementation of TupleStore.
 *
 * <p>Mirrors {@link InMemoryTupleStore} byte-for-byte at the SDK
 * boundary; the difference is durability and concurrency. Schema lives
 * in {@code spec/reference/postgres.sql} (the {@code tup} table).
 *
 * <p>v0.3 (ADR 0017): pass a {@code rules} map to the constructor to
 * enable Postgres-backed rewrite-rule evaluation. {@code check()} then
 * dispatches to the iterative {@link RewriteRulesEvaluator} on
 * direct-lookup miss, issuing one indexed SELECT per hop. Without
 * rules, behaviour is byte-identical to v0.2.
 *
 * <p>Connection handling: callers pass a {@link DataSource}. Each
 * operation borrows a connection for the duration of its work and
 * returns it.
 */
public class PostgresTupleStore implements TupleStore {

    private static final String UNIQUE_VIOLATION = "23505";

    private static final String TUP_COLS =
            "id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by";

    private final DataSource dataSource;
    private final Connection callerConnection;
    private final Clock clock;
    private final Map<String, Map<String, List<RuleNode>>> rules;
    private final int maxDepth;
    private final int maxFanOut;

    public PostgresTupleStore(DataSource dataSource) {
        this(dataSource, Clock.systemUTC(), null,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT);
    }

    public PostgresTupleStore(DataSource dataSource, Clock clock) {
        this(dataSource, clock, null,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT);
    }

    /** v0.3 (ADR 0017): enable Postgres-backed rewrite-rule evaluation. */
    public PostgresTupleStore(DataSource dataSource,
                               Map<String, Map<String, List<RuleNode>>> rules) {
        this(dataSource, Clock.systemUTC(), rules,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT);
    }

    private PostgresTupleStore(DataSource dataSource, Clock clock,
                                Map<String, Map<String, List<RuleNode>>> rules,
                                int maxDepth, int maxFanOut) {
        this.dataSource = dataSource;
        this.callerConnection = null;
        this.clock = clock;
        this.rules = rules;
        this.maxDepth = maxDepth;
        this.maxFanOut = maxFanOut;
    }

    /**
     * ADR 0013 caller-owned-connection constructor. The adopter manages
     * the Connection's transaction lifecycle; this store routes its
     * queries to that connection (no close on end-of-try).
     */
    public PostgresTupleStore(Connection callerConnection) {
        this(callerConnection, Clock.systemUTC(), null,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT);
    }

    public PostgresTupleStore(Connection callerConnection, Clock clock) {
        this(callerConnection, clock, null,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT);
    }

    /** v0.3 (ADR 0017): caller-owned-connection constructor with rewrite rules. */
    public PostgresTupleStore(Connection callerConnection,
                               Map<String, Map<String, List<RuleNode>>> rules) {
        this(callerConnection, Clock.systemUTC(), rules,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT);
    }

    private PostgresTupleStore(Connection callerConnection, Clock clock,
                                Map<String, Map<String, List<RuleNode>>> rules,
                                int maxDepth, int maxFanOut) {
        this.dataSource = null;
        this.callerConnection = callerConnection;
        this.clock = clock;
        this.rules = rules;
        this.maxDepth = maxDepth;
        this.maxFanOut = maxFanOut;
    }

    private Connection acquireConnection() throws SQLException {
        if (callerConnection == null) return dataSource.getConnection();
        return (Connection) Proxy.newProxyInstance(
            Connection.class.getClassLoader(),
            new Class<?>[] { Connection.class },
            (proxy, method, args) -> {
                if ("close".equals(method.getName()) && method.getParameterCount() == 0) {
                    return null;
                }
                try {
                    return method.invoke(callerConnection, args);
                } catch (InvocationTargetException e) {
                    throw e.getCause();
                }
            }
        );
    }

    private static String wireToUuid(String wireId) {
        return Id.decode(wireId).uuid();
    }

    private static final java.util.regex.Pattern OBJECT_ID_WIRE =
            java.util.regex.Pattern.compile("^[a-z]{2,6}_[0-9a-f]{32}$");

    /**
     * Decode an {@code object_id} to a Postgres-bindable UUID. Accepts:
     * <ol>
     *   <li>Wire-format prefixed IDs ({@code <prefix>_<32hex>}) — including
     *       app-defined prefixes that aren't in {@link Id#TYPES}, decoded
     *       via {@link Id#decodeAny(String)}. Closes spec#8.</li>
     *   <li>Raw 32-char hex UUIDs — formatted to canonical form.</li>
     *   <li>Canonical hyphenated UUIDs — passed through.</li>
     * </ol>
     */
    private static UUID objectIdToUuid(String objectId) {
        if (OBJECT_ID_WIRE.matcher(objectId).matches()) {
            return UUID.fromString(Id.decodeAny(objectId).uuid());
        }
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
        String subjectType = rs.getString("subject_type");
        String subjectUuid = rs.getString("subject_id");
        String createdByUuid = rs.getString("created_by");
        return new Tuple(
                Id.encode("tup", tupUuid),
                subjectType,
                Id.encode(subjectType, subjectUuid),
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
        UUID subjectUuid = objectIdToUuid(subjectId);
        UUID createdByUuid = createdBy != null ? UUID.fromString(wireToUuid(createdBy)) : null;
        Instant now = now();
        // ADR 0013: ON CONFLICT DO NOTHING avoids raising 23505 inside
        // an outer transaction (the previous catch-and-SELECT pattern
        // would run the SELECT inside a Postgres-aborted transaction).
        try (Connection conn = acquireConnection()) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO tup (id, subject_type, subject_id, relation, object_type, object_id, created_at, created_by)"
                  + " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                  + " ON CONFLICT (subject_type, subject_id, relation, object_type, object_id) DO NOTHING"
                  + " RETURNING " + TUP_COLS)) {
                ps.setObject(1, tupUuid);
                ps.setString(2, subjectType);
                ps.setObject(3, subjectUuid);
                ps.setString(4, relation);
                ps.setString(5, objectType);
                ps.setObject(6, objectIdToUuid(objectId));
                ps.setTimestamp(7, Timestamp.from(now));
                ps.setObject(8, createdByUuid);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rowToTuple(rs);
                    }
                }
            }
            // Conflict: SELECT the existing row and raise.
            try (PreparedStatement sel = conn.prepareStatement(
                    "SELECT id FROM tup WHERE subject_type = ? AND subject_id = ? AND relation = ?"
                  + " AND object_type = ? AND object_id = ?")) {
                sel.setString(1, subjectType);
                sel.setObject(2, subjectUuid);
                sel.setString(3, relation);
                sel.setString(4, objectType);
                sel.setObject(5, objectIdToUuid(objectId));
                try (ResultSet rs = sel.executeQuery()) {
                    if (rs.next()) {
                        throw new DuplicateTupleError(
                                "Tuple with identical natural key already exists",
                                Id.encode("tup", rs.getString("id"))
                        );
                    }
                }
            }
            // Race: another connection inserted-then-deleted between our
            // ON CONFLICT and SELECT. Surface a generic error so callers can retry.
            throw new SQLException("Tuple natural-key conflict resolved after insert lost the row; retry.");
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void deleteTuple(String tupleId) {
        UUID uuid = UUID.fromString(wireToUuid(tupleId));
        try (Connection conn = acquireConnection();
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
        UUID subjectUuid = objectIdToUuid(subjectId);
        try (Connection conn = acquireConnection();
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

    /** Direct single-row lookup — used by the rules evaluator and the no-rules fast path. */
    private String directLookup(Connection conn,
                                  String subjectType, String subjectId,
                                  String relation, String objectType, String objectId) throws SQLException {
        UUID subjectUuid;
        UUID objectUuid;
        try {
            subjectUuid = objectIdToUuid(subjectId);
            objectUuid = objectIdToUuid(objectId);
        } catch (Exception e) {
            return null;
        }
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id FROM tup WHERE subject_type = ? AND subject_id = ? AND relation = ?"
              + " AND object_type = ? AND object_id = ? LIMIT 1")) {
            ps.setString(1, subjectType);
            ps.setObject(2, subjectUuid);
            ps.setString(3, relation);
            ps.setString(4, objectType);
            ps.setObject(5, objectUuid);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                return Id.encode("tup", rs.getString("id"));
            }
        }
    }

    /** List all tuples matching (objectType, objectId, relation) — used by tuple_to_userset. */
    private List<RewriteRulesEvaluator.SubjectRef> listByObject(Connection conn,
                                                                   String objectType,
                                                                   String objectId,
                                                                   String relation) throws SQLException {
        UUID objectUuid;
        try {
            objectUuid = objectIdToUuid(objectId);
        } catch (Exception e) {
            return List.of();
        }
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, subject_type, subject_id FROM tup"
              + " WHERE object_type = ? AND object_id = ? AND relation = ?")) {
            ps.setString(1, objectType);
            ps.setObject(2, objectUuid);
            ps.setString(3, relation);
            try (ResultSet rs = ps.executeQuery()) {
                List<RewriteRulesEvaluator.SubjectRef> out = new ArrayList<>();
                while (rs.next()) {
                    String tupId = Id.encode("tup", rs.getString("id"));
                    String subjectType = rs.getString("subject_type");
                    UUID subjectUuid = UUID.fromString(rs.getString("subject_id"));
                    String subjectWireId = subjectType + "_" + subjectUuid.toString().replace("-", "");
                    out.add(new RewriteRulesEvaluator.SubjectRef(subjectType, subjectWireId, tupId));
                }
                return out;
            }
        }
    }

    @Override
    public CheckResult check(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId
    ) {
        if (rules == null) {
            return checkAny(subjectType, subjectId, List.of(relation), objectType, objectId);
        }
        // Rules-aware path: use the evaluator with Postgres-backed callbacks.
        try (Connection conn = acquireConnection()) {
            RewriteRulesEvaluator.EvaluationResult res = RewriteRulesEvaluator.evaluate(
                    rules, subjectType, subjectId, relation, objectType, objectId,
                    (st, sid, rel, ot, oid) -> {
                        try {
                            return directLookup(conn, st, sid, rel, ot, oid);
                        } catch (SQLException e) {
                            throw new RuntimeException(e);
                        }
                    },
                    (ot, oid, rel) -> {
                        try {
                            return listByObject(conn, ot, oid, rel);
                        } catch (SQLException e) {
                            throw new RuntimeException(e);
                        }
                    },
                    maxDepth, maxFanOut
            );
            if (!res.allowed()) return CheckResult.denied();
            return CheckResult.allowed(res.matchedTupleId());
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
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
        // Fast path: no rules — single SQL query with relation = ANY.
        if (rules == null) {
            UUID subjectUuid = objectIdToUuid(subjectId);
            try (Connection conn = acquireConnection();
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
                    if (!rs.next()) return CheckResult.denied();
                    return CheckResult.allowed(Id.encode("tup", rs.getString("id")));
                }
            } catch (SQLException e) {
                throw new RuntimeException(e);
            }
        }
        // Rules-aware path: check each relation in turn.
        for (String rel : relations) {
            CheckResult r = check(subjectType, subjectId, rel, objectType, objectId);
            if (r.allowed()) return r;
        }
        return CheckResult.denied();
    }

    // ─── Read accessors ───

    @Override
    public Tuple getTuple(String tupleId) {
        UUID uuid = UUID.fromString(wireToUuid(tupleId));
        try (Connection conn = acquireConnection();
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
        try (Connection conn = acquireConnection();
             PreparedStatement ps = conn.prepareStatement(sql.toString())) {
            int idx = 1;
            ps.setString(idx++, subjectType);
            ps.setObject(idx++, objectIdToUuid(subjectId));
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
        try (Connection conn = acquireConnection();
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
