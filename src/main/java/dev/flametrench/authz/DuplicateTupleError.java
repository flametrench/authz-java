// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Raised when creating a tuple whose 5-key natural identity already
 * exists. The existing tuple's id is exposed via {@link #getExistingTupleId()}
 * so callers can treat the call as idempotent if they choose.
 */
public class DuplicateTupleError extends AuthzError {
    private final String existingTupleId;

    public DuplicateTupleError(String message, String existingTupleId) {
        super(message, "conflict.duplicate_tuple");
        this.existingTupleId = existingTupleId;
    }

    public String getExistingTupleId() {
        return existingTupleId;
    }
}
