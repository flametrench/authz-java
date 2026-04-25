// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import dev.flametrench.ids.Id;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for InMemoryTupleStore. Mirrors the Node + PHP + Python
 * unit suites; behavior is consistent across all four SDKs.
 */
class InMemoryTupleStoreTest {

    private InMemoryTupleStore store;
    private String alice;
    private String bob;
    private String orgAcme;
    private String project42;

    @BeforeEach
    void setUp() {
        store = new InMemoryTupleStore();
        alice = Id.generate("usr");
        bob = Id.generate("usr");
        orgAcme = Id.generate("org");
        project42 = Id.generate("org").substring(4); // bare hex
    }

    @Test
    void createsTupleWithFreshTupId() {
        Tuple t = store.createTuple("usr", alice, "owner", "org", orgAcme, alice);
        assertTrue(t.id().matches("^tup_[0-9a-f]{32}$"));
        assertEquals(alice, t.subjectId());
        assertEquals(alice, t.createdBy());
    }

    @Test
    void rejectsDuplicateNaturalKeyWithExistingIdAttached() {
        Tuple first = store.createTuple("usr", alice, "viewer", "proj", project42);
        DuplicateTupleError err = assertThrows(DuplicateTupleError.class,
                () -> store.createTuple("usr", alice, "viewer", "proj", project42));
        assertEquals(first.id(), err.getExistingTupleId());
    }

    @Test
    void rejectsInvalidRelationName() {
        assertThrows(InvalidFormatError.class,
                () -> store.createTuple("usr", alice, "Owner", "org", orgAcme));
    }

    @Test
    void rejectsInvalidObjectType() {
        assertThrows(InvalidFormatError.class,
                () -> store.createTuple("usr", alice, "viewer", "UPPER", project42));
    }

    @Test
    void acceptsCustomRelations() {
        Tuple t = store.createTuple("usr", alice, "dispatcher", "org", orgAcme);
        assertEquals("dispatcher", t.relation());
    }

    @Test
    void checkExactMatchAllowed() {
        store.createTuple("usr", alice, "editor", "proj", project42);
        CheckResult r = store.check("usr", alice, "editor", "proj", project42);
        assertTrue(r.allowed());
        assertNotNull(r.matchedTupleId());
    }

    @Test
    void checkExactMatchDeniedForDifferentRelation() {
        store.createTuple("usr", alice, "editor", "proj", project42);
        CheckResult r = store.check("usr", alice, "viewer", "proj", project42);
        assertFalse(r.allowed());
        assertNull(r.matchedTupleId());
    }

    @Test
    void noDerivationAdminDoesNotImplyEditor() {
        store.createTuple("usr", alice, "admin", "org", orgAcme);
        CheckResult r = store.check("usr", alice, "editor", "org", orgAcme);
        assertFalse(r.allowed());
    }

    @Test
    void noDerivationEditorDoesNotImplyViewer() {
        store.createTuple("usr", alice, "editor", "proj", project42);
        CheckResult r = store.check("usr", alice, "viewer", "proj", project42);
        assertFalse(r.allowed());
    }

    @Test
    void checkAnyTrueIfAnyMatches() {
        store.createTuple("usr", alice, "editor", "proj", project42);
        CheckResult r = store.checkAny("usr", alice,
                List.of("viewer", "editor", "owner"), "proj", project42);
        assertTrue(r.allowed());
    }

    @Test
    void checkAnyFalseIfNoneMatch() {
        store.createTuple("usr", alice, "editor", "proj", project42);
        CheckResult r = store.checkAny("usr", alice,
                List.of("viewer", "admin"), "proj", project42);
        assertFalse(r.allowed());
    }

    @Test
    void checkAnyRejectsEmptyRelations() {
        assertThrows(EmptyRelationSetError.class,
                () -> store.checkAny("usr", alice, List.of(), "proj", project42));
    }

    @Test
    void deleteTupleRemovesItAndFreesNaturalKey() {
        Tuple t = store.createTuple("usr", alice, "viewer", "proj", project42);
        store.deleteTuple(t.id());
        assertFalse(store.check("usr", alice, "viewer", "proj", project42).allowed());
        Tuple recreated = store.createTuple("usr", alice, "viewer", "proj", project42);
        assertNotEquals(t.id(), recreated.id());
    }

    @Test
    void deleteTupleRaisesForUnknownId() {
        assertThrows(TupleNotFoundError.class,
                () -> store.deleteTuple("tup_deadbeef00000000000000000000ff"));
    }

    @Test
    void cascadeRevokeSubjectDeletesAllTuplesAndReturnsCount() {
        store.createTuple("usr", alice, "owner", "org", orgAcme);
        store.createTuple("usr", alice, "editor", "proj", project42);
        store.createTuple("usr", bob, "member", "org", orgAcme);

        int n = store.cascadeRevokeSubject("usr", alice);
        assertEquals(2, n);
        assertEquals(0, store.listTuplesBySubject("usr", alice, null, 50).data().size());
        assertEquals(1, store.listTuplesBySubject("usr", bob, null, 50).data().size());
    }

    @Test
    void listTuplesByObjectFiltersByRelation() {
        store.createTuple("usr", alice, "viewer", "proj", project42);
        store.createTuple("usr", bob, "viewer", "proj", project42);
        store.createTuple("usr", alice, "editor", "proj", project42);
        Page<Tuple> viewers = store.listTuplesByObject("proj", project42, "viewer", null, 50);
        assertEquals(2, viewers.data().size());
        Page<Tuple> all = store.listTuplesByObject("proj", project42, null, null, 50);
        assertEquals(3, all.data().size());
    }
}
