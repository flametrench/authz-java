// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Contract every authorization backend implements.
 *
 * <p>Exact-match semantics: {@code check()} returns true iff a tuple
 * with the EXACT 5-tuple key exists. No derivation, no inheritance, no
 * group expansion in v0.1. Any implementation that returns true for a
 * missing tuple — even via a reasonable inference — is NOT conformant.
 */
public interface TupleStore {

    Tuple createTuple(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId,
            String createdBy
    );

    default Tuple createTuple(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId
    ) {
        return createTuple(subjectType, subjectId, relation, objectType, objectId, null);
    }

    void deleteTuple(String tupleId);

    /** Delete every tuple with the given subject. Returns count. */
    int cascadeRevokeSubject(String subjectType, String subjectId);

    CheckResult check(
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId
    );

    CheckResult checkAny(
            String subjectType,
            String subjectId,
            java.util.List<String> relations,
            String objectType,
            String objectId
    );

    Tuple getTuple(String tupleId);

    Page<Tuple> listTuplesBySubject(
            String subjectType,
            String subjectId,
            String cursor,
            int limit
    );

    Page<Tuple> listTuplesByObject(
            String objectType,
            String objectId,
            String relation,
            String cursor,
            int limit
    );
}
