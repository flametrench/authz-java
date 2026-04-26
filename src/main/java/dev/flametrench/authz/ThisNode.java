// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * The explicit-tuple set: equivalent to v0.1 check() semantics.
 *
 * <p>In v0.2, ThisNode is always implicitly part of every rule's union
 * — the direct-tuple fast path runs before rule expansion. Listing it
 * explicitly is documentation, not behavior.
 */
public record ThisNode() implements RuleNode {
}
