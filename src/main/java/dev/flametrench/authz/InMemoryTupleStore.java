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
 */
public class InMemoryTupleStore implements TupleStore {

    private final Map<String, Tuple> tuples = new LinkedHashMap<>();
    private final Map<String, String> keyIndex = new HashMap<>(); // natural-key → tup id
    private final Clock clock;

    public InMemoryTupleStore() {
        this(Clock.systemUTC());
    }

    public InMemoryTupleStore(Clock clock) {
        this.clock = clock;
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
        String key = naturalKey(subjectType, subjectId, relation, objectType, objectId);
        String tupId = keyIndex.get(key);
        return tupId == null ? CheckResult.denied() : CheckResult.allowed(tupId);
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
            String key = naturalKey(subjectType, subjectId, relation, objectType, objectId);
            String tupId = keyIndex.get(key);
            if (tupId != null) {
                return CheckResult.allowed(tupId);
            }
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
