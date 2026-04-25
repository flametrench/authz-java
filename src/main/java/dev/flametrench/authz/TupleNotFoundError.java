// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

public class TupleNotFoundError extends AuthzError {
    public TupleNotFoundError(String message) {
        super(message, "not_found");
    }
}
