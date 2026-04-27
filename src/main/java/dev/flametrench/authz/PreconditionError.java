// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * A precondition for the requested operation was not met.
 *
 * <p>Used (initially) when share creation is attempted on behalf of a
 * non-active user — {@code created_by} MUST resolve to a user whose
 * {@code usr.status} is {@code 'active'} per ADR 0012. The DDL FK
 * enforces existence; the status check runs at the SDK layer because
 * the {@code usr} table has no partial-active foreign key.
 *
 * <p>Carries an additional {@code reason} token (e.g.
 * {@code creator_not_active}) matching the convention used by
 * {@code PreconditionError} in the identity and tenancy SDKs.
 */
public class PreconditionError extends AuthzError {
    private final String reason;

    public PreconditionError(String message, String reason) {
        super(message, "precondition." + reason);
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}
