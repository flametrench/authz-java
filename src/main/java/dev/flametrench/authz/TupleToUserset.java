// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Parent-child inheritance via a relation traversal.
 *
 * <p>{@code new TupleToUserset("parent_org", "viewer")} on a rule for
 * {@code proj.viewer} means: enumerate all {@code (*, parent_org,
 * this_proj)} tuples — for each such tuple's subject (an org),
 * recursively check whether the original subject has {@code viewer}
 * on that org.
 */
public record TupleToUserset(
        String tuplesetRelation,
        String computedUsersetRelation
) implements RuleNode {
}
