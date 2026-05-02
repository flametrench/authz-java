// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import dev.flametrench.ids.DecodedId;
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
    private final Connection callerConnection;
    private final Clock clock;
    /** v0.3 (ADR 0017): nullable rule registry; null => exact-match only. */
    private final java.util.Map<String, java.util.Map<String, java.util.List<RuleNode>>> rules;
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

    /**
     * v0.3 (ADR 0017): full constructor accepting an optional rule
     * registry. With {@code rules == null}, behavior is byte-identical
     * to v0.2 (exact-match only). With rules, {@code check()}
     * evaluates rewrite rules via iterative expansion against
     * Postgres — same algorithm InMemoryTupleStore uses.
     */
    public PostgresTupleStore(
            DataSource dataSource,
            Clock clock,
            java.util.Map<String, java.util.Map<String, java.util.List<RuleNode>>> rules,
            int maxDepth,
            int maxFanOut
    ) {
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

    public PostgresTupleStore(
            Connection callerConnection,
            Clock clock,
            java.util.Map<String, java.util.Map<String, java.util.List<RuleNode>>> rules,
            int maxDepth,
            int maxFanOut
    ) {
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
     * v0.3 (ADR 0017) — accept subject ids in any of three shapes:
     * wire format with usr_, wire format with any registered prefix
     * (org_<hex> for tuple_to_userset parent hops), or bare canonical
     * UUID. Mirrors {@link #objectIdToUuid}.
     */
    private static UUID subjectIdToUuid(String subjectId) {
        return subjectIdToUuid(subjectId, null);
    }

    /**
     * security-audit-v0.3.md M9: when a {@code subjectType} is supplied,
     * assert the wire-id's prefix matches it. Pre-fix this helper accepted
     * any {@code <word>_<uuid>} string, so a caller passing a stale
     * (subjectType, subjectId) pair where the id's prefix didn't match
     * the type was silently coerced.
     */
    private static UUID subjectIdToUuid(String subjectId, String subjectType) {
        if (OBJECT_ID_WIRE.matcher(subjectId).matches()) {
            DecodedId decoded = Id.decodeAny(subjectId);
            if (subjectType != null && !decoded.type().equals(subjectType)) {
                throw new InvalidFormatError(
                        "subjectId " + subjectId + " prefix does not match subjectType " + subjectType,
                        "subject_id"
                );
            }
            return UUID.fromString(decoded.uuid());
        }
        if (subjectId.length() == 32) {
            return UUID.fromString(formatBareHex(subjectId));
        }
        return UUID.fromString(subjectId);
    }

    private static String formatBareHex(String s) {
        return s.substring(0, 8) + "-" + s.substring(8, 12)
                + "-" + s.substring(12, 16) + "-" + s.substring(16, 20)
                + "-" + s.substring(20);
    }

    /** UUID 01234567-89ab-... → bare 32-hex 0123456789ab... */
    private static String uuidHyphensToBare(String hyphenated) {
        return hyphenated.replace("-", "");
    }

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
        UUID subjectUuid = subjectIdToUuid(subjectId, subjectType);
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
        UUID subjectUuid = subjectIdToUuid(subjectId, subjectType);
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

    @Override
    public CheckResult check(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId
    ) {
        // v0.1 fast path: direct natural-key lookup.
        String direct = directLookup(subjectType, subjectId, relation, objectType, objectId);
        if (direct != null) {
            return CheckResult.allowed(direct);
        }
        // ADR 0017 path: rule expansion only on direct miss AND when
        // rules are registered. With rules=null, behavior is byte-
        // identical to v0.2.
        if (this.rules == null) {
            return CheckResult.denied();
        }
        // security-audit-v0.3.md M1: pin a single Connection for the
        // whole rule-eval recursion. Pre-fix every directLookup /
        // listByObject hop borrowed a fresh DataSource connection, so
        // a deep tuple_to_userset chain could fan checkouts across
        // one logical check. Bound to one connection now; read-skew is
        // still possible under concurrent writers (documented as a
        // v0.3 limitation in ADR 0017).
        try (Connection conn = acquireConnection()) {
            final Connection pinned = conn;
            RewriteRulesEvaluator.EvaluationResult result = RewriteRulesEvaluator.evaluate(
                    this.rules,
                    subjectType, subjectId, relation, objectType, objectId,
                    (st, si, r, ot, oi) -> directLookupOn(pinned, st, si, r, ot, oi),
                    (ot, oi, r) -> listByObjectOn(pinned, ot, oi, r),
                    this.maxDepth,
                    this.maxFanOut
            );
            return result.allowed()
                    ? CheckResult.allowed(result.matchedTupleId())
                    : CheckResult.denied();
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
        // Fast path: when no rules are registered, a single SELECT with
        // `relation = ANY(?)` short-circuits the whole set in one round
        // trip. Preserves v0.2 behavior.
        if (this.rules == null) {
            UUID subjectUuid = subjectIdToUuid(subjectId, subjectType);
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
        // With rules, evaluate each relation in turn until first match.
        for (String relation : relations) {
            CheckResult r = check(subjectType, subjectId, relation, objectType, objectId);
            if (r.allowed()) return r;
        }
        return CheckResult.denied();
    }

    /**
     * Direct natural-key lookup against Postgres — fast-path entry that
     * borrows its own connection. The rule-eval recursion uses
     * {@link #directLookupOn} with a connection pinned by {@link #check}.
     */
    private String directLookup(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId
    ) {
        try (Connection conn = acquireConnection()) {
            return directLookupOn(conn, subjectType, subjectId, relation, objectType, objectId);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * security-audit-v0.3.md M1 — direct lookup against an explicit
     * Connection. Rule-eval recursion calls this with one connection
     * pinned for the whole evaluate(), so deep tuple_to_userset chains
     * don't fan DataSource checkouts across one check.
     */
    private String directLookupOn(
            Connection conn,
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId
    ) {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id FROM tup WHERE subject_type = ? AND subject_id = ?"
              + " AND relation = ? AND object_type = ? AND object_id = ? LIMIT 1")) {
            ps.setString(1, subjectType);
            ps.setObject(2, subjectIdToUuid(subjectId, subjectType));
            ps.setString(3, relation);
            ps.setString(4, objectType);
            ps.setObject(5, objectIdToUuid(objectId));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                return Id.encode("tup", rs.getString("id"));
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Enumerate tuples on (object, relation). Used by tuple_to_userset.
     *
     * <p>Returned subjectId is wire-format prefixed with the row's
     * subject_type (e.g. {@code org_<hex>} for parent_org tuples), so
     * the evaluator can pass it through as the next-hop objectId.
     */
    private List<RewriteRulesEvaluator.SubjectRef> listByObjectOn(
            Connection conn, String objectType, String objectId, String relation
    ) {
        StringBuilder sql = new StringBuilder(
                "SELECT id, subject_type, subject_id FROM tup"
              + " WHERE object_type = ? AND object_id = ?");
        if (relation != null) sql.append(" AND relation = ?");
        try (PreparedStatement ps = conn.prepareStatement(sql.toString())) {
            ps.setString(1, objectType);
            ps.setObject(2, objectIdToUuid(objectId));
            if (relation != null) ps.setString(3, relation);
            try (ResultSet rs = ps.executeQuery()) {
                List<RewriteRulesEvaluator.SubjectRef> out = new java.util.ArrayList<>();
                while (rs.next()) {
                    String subType = rs.getString("subject_type");
                    String subIdHex = uuidHyphensToBare(rs.getString("subject_id"));
                    out.add(new RewriteRulesEvaluator.SubjectRef(
                            subType,
                            subType + "_" + subIdHex,
                            Id.encode("tup", rs.getString("id"))
                    ));
                }
                return out;
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
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
            ps.setObject(idx++, subjectIdToUuid(subjectId, subjectType));
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
