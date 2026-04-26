// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import dev.flametrench.ids.Id;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for v0.2 rewrite-rule evaluation in the Java SDK.
 * Mirrors authz-python/tests/test_rewrite_rules.py and the Node + PHP
 * test suites exactly so any behavioral drift surfaces as a failure.
 */
class RewriteRulesTest {

    private String alice;
    private String orgAcme;
    private String proj42;

    @BeforeEach
    void setUp() {
        alice = Id.generate("usr");
        orgAcme = Id.generate("org").substring(4);
        proj42 = Id.generate("org").substring(4);
    }

    @Test
    void noRulesMeansNoDerivation() {
        var store = new InMemoryTupleStore();
        store.createTuple("usr", alice, "editor", "proj", proj42);
        var result = store.check("usr", alice, "viewer", "proj", proj42);
        assertFalse(result.allowed());
    }

    @Test
    void emptyRulesMapMeansNoDerivation() {
        var store = InMemoryTupleStore.withRules(Map.of());
        store.createTuple("usr", alice, "editor", "proj", proj42);
        var result = store.check("usr", alice, "viewer", "proj", proj42);
        assertFalse(result.allowed());
    }

    @Test
    void editorImpliesViewer() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ThisNode(), new ComputedUserset("editor"))
                )
        );
        var store = InMemoryTupleStore.withRules(rules);
        var editor = store.createTuple("usr", alice, "editor", "proj", proj42);
        var result = store.check("usr", alice, "viewer", "proj", proj42);
        assertTrue(result.allowed());
        assertEquals(editor.id(), result.matchedTupleId());
    }

    @Test
    void adminImpliesEditorImpliesViewerChain() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ThisNode(), new ComputedUserset("editor")),
                        "editor", List.of(new ThisNode(), new ComputedUserset("admin"))
                )
        );
        var store = InMemoryTupleStore.withRules(rules);
        var admin = store.createTuple("usr", alice, "admin", "proj", proj42);
        var result = store.check("usr", alice, "viewer", "proj", proj42);
        assertTrue(result.allowed());
        assertEquals(admin.id(), result.matchedTupleId());
    }

    @Test
    void missingIntermediateRuleBreaksChain() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ThisNode(), new ComputedUserset("editor"))
                )
        );
        var store = InMemoryTupleStore.withRules(rules);
        store.createTuple("usr", alice, "admin", "proj", proj42);
        var result = store.check("usr", alice, "viewer", "proj", proj42);
        assertFalse(result.allowed());
    }

    @Test
    void orgAdminImpliesProjAdminViaParentOrg() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "admin", List.of(
                                new ThisNode(),
                                new TupleToUserset("parent_org", "admin")
                        )
                )
        );
        var store = InMemoryTupleStore.withRules(rules);
        var orgAdmin = store.createTuple("usr", alice, "admin", "org", orgAcme);
        store.createTuple("org", orgAcme, "parent_org", "proj", proj42);
        var result = store.check("usr", alice, "admin", "proj", proj42);
        assertTrue(result.allowed());
        assertEquals(orgAdmin.id(), result.matchedTupleId());
    }

    @Test
    void orgMemberDoesNotImplyProjAdmin() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "admin", List.of(
                                new ThisNode(),
                                new TupleToUserset("parent_org", "admin")
                        )
                )
        );
        var store = InMemoryTupleStore.withRules(rules);
        store.createTuple("usr", alice, "member", "org", orgAcme);
        store.createTuple("org", orgAcme, "parent_org", "proj", proj42);
        var result = store.check("usr", alice, "admin", "proj", proj42);
        assertFalse(result.allowed());
    }

    @Test
    void selfReferentialCycleTerminatesSilently() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ThisNode(), new ComputedUserset("viewer"))
                )
        );
        var store = InMemoryTupleStore.withRules(rules);
        var result = store.check("usr", alice, "viewer", "proj", proj42);
        assertFalse(result.allowed());
    }

    @Test
    void twoNodeCycleTerminatesSilently() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ThisNode(), new ComputedUserset("editor")),
                        "editor", List.of(new ThisNode(), new ComputedUserset("viewer"))
                )
        );
        var store = InMemoryTupleStore.withRules(rules);
        var result = store.check("usr", alice, "viewer", "proj", proj42);
        assertFalse(result.allowed());
    }

    @Test
    void depthLimitRaises() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "r0", List.of(new ThisNode(), new ComputedUserset("r1")),
                        "r1", List.of(new ThisNode(), new ComputedUserset("r2")),
                        "r2", List.of(new ThisNode(), new ComputedUserset("r3")),
                        "r3", List.of(new ThisNode(), new ComputedUserset("r4"))
                )
        );
        var store = new InMemoryTupleStore(
                java.time.Clock.systemUTC(), rules, 2,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT
        );
        assertThrows(EvaluationLimitExceededError.class,
                () -> store.check("usr", alice, "r0", "proj", proj42));
    }

    @Test
    void fanOutLimitRaises() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "admin", List.of(
                                new ThisNode(),
                                new TupleToUserset("parent_org", "admin")
                        )
                )
        );
        var store = new InMemoryTupleStore(
                java.time.Clock.systemUTC(), rules,
                RewriteRulesEvaluator.DEFAULT_MAX_DEPTH, 3
        );
        for (int i = 0; i < 5; i++) {
            store.createTuple(
                    "org", Id.generate("org").substring(4),
                    "parent_org", "proj", proj42
            );
        }
        assertThrows(EvaluationLimitExceededError.class,
                () -> store.check("usr", alice, "admin", "proj", proj42));
    }

    @Test
    void directMatchShortCircuitsRules() {
        Map<String, Map<String, List<RuleNode>>> rules = Map.of(
                "proj", Map.of(
                        "viewer", List.of(new ThisNode(), new ComputedUserset("viewer"))
                )
        );
        var store = new InMemoryTupleStore(
                java.time.Clock.systemUTC(), rules, 2,
                RewriteRulesEvaluator.DEFAULT_MAX_FAN_OUT
        );
        var direct = store.createTuple("usr", alice, "viewer", "proj", proj42);
        var result = store.check("usr", alice, "viewer", "proj", proj42);
        assertTrue(result.allowed());
        assertEquals(direct.id(), result.matchedTupleId());
    }
}
