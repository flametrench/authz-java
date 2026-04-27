// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Returned by {@link ShareStore#createShare}.
 *
 * <p>The plaintext {@code token} is observable here ONLY; the SDK
 * persists only its SHA-256 hash. Callers MUST surface the token to
 * the share recipient at this point and never log it.
 */
public record CreateShareResult(Share share, String token) {
}
