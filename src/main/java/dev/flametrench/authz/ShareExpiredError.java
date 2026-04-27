// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

public class ShareExpiredError extends AuthzError {
    public ShareExpiredError() {
        this("Share has expired");
    }

    public ShareExpiredError(String message) {
        super(message, "share_expired");
    }
}
