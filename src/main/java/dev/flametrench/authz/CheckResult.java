// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Returned by {@code check()} and {@code checkAny()}.
 *
 * @param allowed true iff a matching tuple exists
 * @param matchedTupleId opaque tup_ id of the matched tuple, or null
 *                       when {@code allowed} is false (or if the
 *                       implementation chooses not to disclose).
 */
public record CheckResult(boolean allowed, String matchedTupleId) {
    public static CheckResult denied() {
        return new CheckResult(false, null);
    }

    public static CheckResult allowed(String matchedTupleId) {
        return new CheckResult(true, matchedTupleId);
    }
}
