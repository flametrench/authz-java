// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Sealed marker for the three rewrite-rule node variants in v0.2.
 *
 * <p>See ADR 0007 for the full design rationale. Use pattern matching
 * to narrow to a concrete type when consuming rule data:
 *
 * <pre>{@code
 * if (node instanceof ComputedUserset cu) {
 *     // recurse with cu.relation()
 * }
 * }</pre>
 */
public sealed interface RuleNode
        permits ThisNode, ComputedUserset, TupleToUserset {
}
