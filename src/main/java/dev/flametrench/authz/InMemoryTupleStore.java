// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import dev.flametrench.ids.Id;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reference in-memory TupleStore. O(1) check() via secondary natural-key
 * index; deterministic for tests.
 *
 * <p>v0.2 adds optional rewrite-rule support. With {@code rules == null}
 * the store behaves byte-identically to v0.1; with rules registered,
 * {@code check()} evaluates them on direct-lookup miss per ADR 0007.
 */
public class InMemoryTupleStore implements TupleStore {

    private final Map<String, Tuple> tuples = new LinkedHashMap<>();
    private final Map<String, String> keyIndex = new HashMap<>(); // natural-key → tup id
    private final Clock clock;
    private final Map<String, Map<String, List<RuleNode>>> rules;
    private final int maxDepth;
    private final int maxFanOut;

    public InMemoryTupleStore() {
        this(Clock.systemUTC(), null,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT);
    }

    public InMemoryTupleStore(Clock clock) {
        this(clock, null,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT);
    }

    /**
     * v0.2 constructor: register rewrite rules at construction time.
     *
     * @param rules nested map of (objectType -> relation -> rule). null
     *              means no rules; behavior is identical to v0.1.
     */
    public InMemoryTupleStore(
            Clock clock,
            Map<String, Map<String, List<RuleNode>>> rules,
            int maxDepth,
            int maxFanOut
    ) {
        this.clock = clock;
        this.rules = rules;
        this.maxDepth = maxDepth;
        this.maxFanOut = maxFanOut;
    }

    /** Convenience: rules with system-UTC clock and spec-floor limits. */
    public static InMemoryTupleStore withRules(
            Map<String, Map<String, List<RuleNode>>> rules
    ) {
        return new InMemoryTupleStore(
                Clock.systemUTC(), rules,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT
        );
    }

    private static String naturalKey(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId
    ) {
        return subjectType + "|" + subjectId + "|" + relation + "|" + objectType + "|" + objectId;
    }

    private static void validate(String relation, String objectType) {
        if (!Patterns.RELATION_NAME.matcher(relation).matches()) {
            throw new InvalidFormatError(
                    "relation '" + relation + "' must match " + Patterns.RELATION_NAME.pattern(),
                    "relation");
        }
        if (!Patterns.TYPE_PREFIX.matcher(objectType).matches()) {
            throw new InvalidFormatError(
                    "objectType '" + objectType + "' must match " + Patterns.TYPE_PREFIX.pattern(),
                    "object_type");
        }
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
        String key = naturalKey(subjectType, subjectId, relation, objectType, objectId);
        String existing = keyIndex.get(key);
        if (existing != null) {
            throw new DuplicateTupleError(
                    "Tuple with identical natural key already exists",
                    existing);
        }
        Tuple tup = new Tuple(
                Id.generate("tup"),
                subjectType,
                subjectId,
                relation,
                objectType,
                objectId,
                Instant.now(clock),
                createdBy
        );
        tuples.put(tup.id(), tup);
        keyIndex.put(key, tup.id());
        return tup;
    }

    @Override
    public void deleteTuple(String tupleId) {
        Tuple tup = tuples.get(tupleId);
        if (tup == null) {
            throw new TupleNotFoundError("Tuple " + tupleId + " not found");
        }
        tuples.remove(tupleId);
        keyIndex.remove(naturalKey(
                tup.subjectType(),
                tup.subjectId(),
                tup.relation(),
                tup.objectType(),
                tup.objectId()));
    }

    @Override
    public int cascadeRevokeSubject(String subjectType, String subjectId) {
        List<String> toDelete = new ArrayList<>();
        for (Map.Entry<String, Tuple> e : tuples.entrySet()) {
            Tuple t = e.getValue();
            if (t.subjectType().equals(subjectType) && t.subjectId().equals(subjectId)) {
                toDelete.add(e.getKey());
            }
        }
        for (String id : toDelete) {
            Tuple t = tuples.remove(id);
            keyIndex.remove(naturalKey(
                    t.subjectType(),
                    t.subjectId(),
                    t.relation(),
                    t.objectType(),
                    t.objectId()));
        }
        return toDelete.size();
    }

    // ─── check() primitives ───

    @Override
    public CheckResult check(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId
    ) {
        // v0.1 fast path: direct natural-key lookup. Returns immediately
        // on a direct hit regardless of whether rules are registered.
        String key = naturalKey(subjectType, subjectId, relation, objectType, objectId);
        String tupId = keyIndex.get(key);
        if (tupId != null) {
            return CheckResult.allowed(tupId);
        }

        // v0.2 path: rule expansion only on direct miss AND rules registered.
        if (rules == null) {
            return CheckResult.denied();
        }

        var result = RewriteRulesEvaluator.evaluate(
                rules,
                subjectType, subjectId,
                relation, objectType, objectId,
                this::directLookup,
                this::listByObject,
                maxDepth,
                maxFanOut
        );
        return result.allowed()
                ? CheckResult.allowed(result.matchedTupleId())
                : CheckResult.denied();
    }

    /** Direct natural-key lookup callback for the rule evaluator. */
    private String directLookup(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId
    ) {
        return keyIndex.get(naturalKey(subjectType, subjectId, relation, objectType, objectId));
    }

    /** List tuples on an object filtered by relation, for tuple_to_userset. */
    private List<RewriteRulesEvaluator.SubjectRef> listByObject(
            String objectType, String objectId, String relation
    ) {
        List<RewriteRulesEvaluator.SubjectRef> out = new ArrayList<>();
        for (Tuple t : tuples.values()) {
            if (!t.objectType().equals(objectType) || !t.objectId().equals(objectId)) continue;
            if (relation != null && !t.relation().equals(relation)) continue;
            out.add(new RewriteRulesEvaluator.SubjectRef(
                    t.subjectType(), t.subjectId(), t.id()
            ));
        }
        return out;
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
        for (String relation : relations) {
            // Reuse rule-aware check() so checkAny benefits from rewrites.
            CheckResult r = check(subjectType, subjectId, relation, objectType, objectId);
            if (r.allowed()) return r;
        }
        return CheckResult.denied();
    }

    // ─── Read accessors ───

    @Override
    public Tuple getTuple(String tupleId) {
        Tuple tup = tuples.get(tupleId);
        if (tup == null) {
            throw new TupleNotFoundError("Tuple " + tupleId + " not found");
        }
        return tup;
    }

    @Override
    public Page<Tuple> listTuplesBySubject(
            String subjectType,
            String subjectId,
            String cursor,
            int limit
    ) {
        List<Tuple> matching = new ArrayList<>();
        for (Tuple t : tuples.values()) {
            if (t.subjectType().equals(subjectType) && t.subjectId().equals(subjectId)) {
                matching.add(t);
            }
        }
        matching.sort(Comparator.comparing(Tuple::id));
        return paginate(matching, cursor, limit);
    }

    @Override
    public Page<Tuple> listTuplesByObject(
            String objectType,
            String objectId,
            String relation,
            String cursor,
            int limit
    ) {
        List<Tuple> matching = new ArrayList<>();
        for (Tuple t : tuples.values()) {
            if (!t.objectType().equals(objectType) || !t.objectId().equals(objectId)) continue;
            if (relation != null && !t.relation().equals(relation)) continue;
            matching.add(t);
        }
        matching.sort(Comparator.comparing(Tuple::id));
        return paginate(matching, cursor, limit);
    }

    private static Page<Tuple> paginate(List<Tuple> all, String cursor, int limit) {
        int start = 0;
        if (cursor != null) {
            start = 0;
            for (int i = 0; i < all.size(); i++) {
                if (all.get(i).id().compareTo(cursor) > 0) {
                    start = i;
                    break;
                }
                start = i + 1;
            }
        }
        int end = Math.min(start + limit, all.size());
        List<Tuple> slice = all.subList(start, end);
        String nextCursor = (start + limit) < all.size() && !slice.isEmpty()
                ? slice.get(slice.size() - 1).id()
                : null;
        return new Page<>(new ArrayList<>(slice), nextCursor);
    }
}
