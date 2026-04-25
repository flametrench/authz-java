// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Raised when {@code checkAny} is called with an empty relations array.
 * The spec requires this to be an error rather than a silent {@code false}.
 */
public class EmptyRelationSetError extends AuthzError {
    public EmptyRelationSetError() {
        super("checkAny() relations array must be non-empty",
                "invalid_format.relations");
    }
}
