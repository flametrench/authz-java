// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

public class ShareConsumedError extends AuthzError {
    public ShareConsumedError() {
        this("Share has already been consumed");
    }

    public ShareConsumedError(String message) {
        super(message, "share_consumed");
    }
}
