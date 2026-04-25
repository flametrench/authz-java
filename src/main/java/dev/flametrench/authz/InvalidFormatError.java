// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Raised when an input violates a spec-defined format rule
 * (e.g. relation name pattern or object-type prefix pattern).
 */
public class InvalidFormatError extends AuthzError {
    private final String field;

    public InvalidFormatError(String message, String field) {
        super(message, "invalid_format." + field);
        this.field = field;
    }

    public String getField() {
        return field;
    }
}
