// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Generic violation of {@link ShareStore#verifyShareToken} precondition:
 * token doesn't match any row, or hash comparison failed. Deliberately
 * conflated to avoid a timing oracle distinguishing "no such hash" from
 * "hash collision but mismatch."
 */
public class InvalidShareTokenError extends AuthzError {
    public InvalidShareTokenError() {
        this("Invalid share token");
    }

    public InvalidShareTokenError(String message) {
        super(message, "invalid_share_token");
    }
}
