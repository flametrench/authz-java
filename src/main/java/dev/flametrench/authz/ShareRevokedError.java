// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

public class ShareRevokedError extends AuthzError {
    public ShareRevokedError() {
        this("Share has been revoked");
    }

    public ShareRevokedError(String message) {
        super(message, "share_revoked");
    }
}
