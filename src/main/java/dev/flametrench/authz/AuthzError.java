// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Base class for every authorization-layer error. Carries a stable
 * {@code code} matching the OpenAPI Error envelope.
 */
public class AuthzError extends RuntimeException {
    private final String code;

    public AuthzError(String message, String code) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
