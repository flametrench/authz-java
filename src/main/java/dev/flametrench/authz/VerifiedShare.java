// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Returned by {@link ShareStore#verifyShareToken} on success.
 *
 * <p>This is enough information to render the resource at the given
 * relation; it is NOT an authenticated principal and MUST NOT be
 * promoted to a session.
 */
public record VerifiedShare(
        String shareId,
        String objectType,
        String objectId,
        String relation
) {
}
