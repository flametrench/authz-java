// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;

/**
 * Authorization rewrite-rule evaluator — v0.2 reference per ADR 0007.
 *
 * <p>Layered exactly as the ADR prescribes:
 * <ol>
 *   <li>Direct lookup. If a tuple matches, return it. v0.1 fast path.</li>
 *   <li>Rule expansion. If a rule exists for {@code (objectType,
 *       relation)}, expand its primitives. Each primitive recurses
 *       with bounded depth and tracks a frame stack for cycle
 *       detection.</li>
 *   <li>Short-circuit on first match. Union semantics; any sub-eval
 *       returning allowed ends the evaluation.</li>
 * </ol>
 */
public final class RewriteRulesEvaluator {

    public static final int DEFAULT_MAX_DEPTH = 8;
    public static final int DEFAULT_MAX_FAN_OUT = 1024;

    /** {@code (subjectType, subjectId, relation, objectType, objectId) -> tup_id|null} */
    @FunctionalInterface
    public interface DirectLookup {
        String lookup(
                String subjectType,
                String subjectId,
                String relation,
                String objectType,
                String objectId
        );
    }

    /**
     * One result row from {@code listByObject}: a tuple's subject and
     * its tup_id.
     */
    public record SubjectRef(String subjectType, String subjectId, String tupId) {
    }

    /** {@code (objectType, objectId, relation) -> list of subject refs} */
    @FunctionalInterface
    public interface ListByObject {
        List<SubjectRef> list(String objectType, String objectId, String relation);
    }

    public record EvaluationResult(boolean allowed, String matchedTupleId) {
    }

    private RewriteRulesEvaluator() {
        // utility
    }

    public static EvaluationResult evaluate(
            Map<String, Map<String, List<RuleNode>>> rules,
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId,
            DirectLookup directLookup,
            ListByObject listByObject,
            int maxDepth,
            int maxFanOut
    ) {
        return go(
                rules, subjectType, subjectId,
                relation, objectType, objectId,
                directLookup, listByObject,
                new HashSet<>(), 0,
                maxDepth, maxFanOut
        );
    }

    private static EvaluationResult go(
            Map<String, Map<String, List<RuleNode>>> rules,
            String subjectType,
            String subjectId,
            String relation,
            String objectType,
            String objectId,
            DirectLookup directLookup,
            ListByObject listByObject,
            Set<String> stack,
            int depth,
            int maxDepth,
            int maxFanOut
    ) {
        // 1. Direct lookup.
        String direct = directLookup.lookup(
                subjectType, subjectId, relation, objectType, objectId
        );
        if (direct != null) {
            return new EvaluationResult(true, direct);
        }

        // 2. Rule expansion.
        if (rules == null) {
            return new EvaluationResult(false, null);
        }
        Map<String, List<RuleNode>> objectRules = rules.get(objectType);
        if (objectRules == null) {
            return new EvaluationResult(false, null);
        }
        List<RuleNode> rule = objectRules.get(relation);
        if (rule == null) {
            return new EvaluationResult(false, null);
        }

        // Cycle detection.
        String frameKey = relation + "|" + objectType + "|" + objectId;
        if (stack.contains(frameKey)) {
            return new EvaluationResult(false, null);
        }

        // Depth bound.
        if (depth >= maxDepth) {
            throw new EvaluationLimitExceededError(
                    "Rule evaluation exceeded depth limit (" + maxDepth + ") at "
                            + objectType + "." + relation
                            + " for " + objectType + "_" + objectId
            );
        }

        Set<String> newStack = new HashSet<>(stack);
        newStack.add(frameKey);

        for (RuleNode node : rule) {
            if (node instanceof ThisNode) {
                continue; // covered by step 1
            }
            if (node instanceof ComputedUserset cu) {
                EvaluationResult r = go(
                        rules, subjectType, subjectId,
                        cu.relation(), objectType, objectId,
                        directLookup, listByObject,
                        newStack, depth + 1,
                        maxDepth, maxFanOut
                );
                if (r.allowed()) return r;
                continue;
            }
            if (node instanceof TupleToUserset ttu) {
                List<SubjectRef> related =
                        listByObject.list(objectType, objectId, ttu.tuplesetRelation());
                if (related.size() > maxFanOut) {
                    throw new EvaluationLimitExceededError(
                            "tuple_to_userset fan-out exceeded (" + related.size()
                                    + " > " + maxFanOut + ") at "
                                    + objectType + "." + relation
                                    + " via " + ttu.tuplesetRelation()
                    );
                }
                for (SubjectRef ref : related) {
                    EvaluationResult r = go(
                            rules, subjectType, subjectId,
                            ttu.computedUsersetRelation(),
                            ref.subjectType(), ref.subjectId(),
                            directLookup, listByObject,
                            newStack, depth + 1,
                            maxDepth, maxFanOut
                    );
                    if (r.allowed()) return r;
                }
                continue;
            }
            throw new IllegalStateException("Unknown rule node: " + node.getClass());
        }

        return new EvaluationResult(false, null);
    }
}
