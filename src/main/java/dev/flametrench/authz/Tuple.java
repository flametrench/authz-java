// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import java.time.Instant;
import java.util.Objects;

/**
 * A relational tuple — the sole authz primitive in v0.1.
 *
 * <p>The natural key is {@code (subjectType, subjectId, relation,
 * objectType, objectId)}. {@code id} is the opaque {@code tup_}
 * identifier.
 */
public record Tuple(
        String id,
        String subjectType,
        String subjectId,
        String relation,
        String objectType,
        String objectId,
        Instant createdAt,
        String createdBy
) {
    public Tuple {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(subjectType, "subjectType");
        Objects.requireNonNull(subjectId, "subjectId");
        Objects.requireNonNull(relation, "relation");
        Objects.requireNonNull(objectType, "objectType");
        Objects.requireNonNull(objectId, "objectId");
        Objects.requireNonNull(createdAt, "createdAt");
        // createdBy may be null
    }
}
