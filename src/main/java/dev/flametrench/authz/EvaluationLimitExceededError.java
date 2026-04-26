// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Rewrite-rule evaluation exceeded a configured bound (depth or fan-out).
 *
 * <p>Bounds are configurable per-store; the spec floor is depth=8,
 * fan-out=1024. Apps hitting this in practice should restructure their
 * rule set or explicitly raise the limit.
 *
 * <p>v0.2; see ADR 0007.
 */
public class EvaluationLimitExceededError extends AuthzError {
    public EvaluationLimitExceededError(String message) {
        super(message, "evaluation_limit_exceeded");
    }
}
