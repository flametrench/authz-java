// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import java.time.Instant;

/**
 * The public share record.
 *
 * <p>Token storage (SHA-256 → BYTEA) is internal; the plaintext bearer
 * credential is returned ONCE on {@link ShareStore#createShare} and
 * never persisted nor exposed via this record.
 */
public record Share(
        String id,
        String objectType,
        String objectId,
        String relation,
        String createdBy,
        Instant expiresAt,
        boolean singleUse,
        /** Set on first verify when {@code singleUse} is true. */
        Instant consumedAt,
        /** Soft-delete timestamp. */
        Instant revokedAt,
        Instant createdAt
) {
}
