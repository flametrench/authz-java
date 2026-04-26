// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

/**
 * Role implication on the same object.
 *
 * <p>{@code new ComputedUserset("editor")} on a rule for
 * {@code proj.viewer} means: anyone holding {@code editor} on this
 * same project also has {@code viewer}. The check recurses with the
 * same object, different relation.
 */
public record ComputedUserset(String relation) implements RuleNode {
}
