// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

public class ShareNotFoundError extends AuthzError {
    public ShareNotFoundError(String message) {
        super(message, "not_found");
    }
}
