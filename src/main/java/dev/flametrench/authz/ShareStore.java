// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Contract every share-token backend implements.
 *
 * <p>Verification ordering is normative (per ADR 0012):
 * <ol>
 *   <li>Hash input via SHA-256.</li>
 *   <li>Look up by {@code token_hash}; missing → {@link InvalidShareTokenError}.</li>
 *   <li>Constant-time-compare; mismatch → {@link InvalidShareTokenError}.</li>
 *   <li>{@code revokedAt} non-null → {@link ShareRevokedError}.</li>
 *   <li>{@code singleUse} and {@code consumedAt} non-null → {@link ShareConsumedError}.</li>
 *   <li>{@code expiresAt <= now} → {@link ShareExpiredError}.</li>
 *   <li>If {@code singleUse}: transactionally set {@code consumedAt = now}.</li>
 * </ol>
 */
public interface ShareStore {

    /** Spec-mandated upper bound on share lifetime: 365 days. */
    long MAX_TTL_SECONDS = 365L * 24 * 60 * 60;

    CreateShareResult createShare(
            String objectType,
            String objectId,
            String relation,
            String createdBy,
            long expiresInSeconds,
            boolean singleUse
    );

    /** Convenience overload — non-single-use share. */
    default CreateShareResult createShare(
            String objectType,
            String objectId,
            String relation,
            String createdBy,
            long expiresInSeconds
    ) {
        return createShare(objectType, objectId, relation, createdBy, expiresInSeconds, false);
    }

    Share getShare(String shareId);

    VerifiedShare verifyShareToken(String token);

    /**
     * Idempotent. Calling on an already-revoked share returns the
     * existing record with the original {@code revokedAt}; not an error.
     */
    Share revokeShare(String shareId);

    Page<Share> listSharesForObject(
            String objectType,
            String objectId,
            String cursor,
            int limit
    );
}
