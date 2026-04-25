// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Flametrench v0.1 conformance suite — Java / JUnit 5 harness for the
 * authorization capability.
 *
 * <p>Exercises check, check_any, and create_tuple (uniqueness + format)
 * against the fixture corpus vendored from
 * github.com/flametrench/spec/conformance/fixtures/authorization/.
 */
class ConformanceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode loadFixture(String relativePath) throws IOException {
        String resource = "/conformance/fixtures/" + relativePath;
        try (InputStream in = ConformanceTest.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("Fixture not found on classpath: " + resource);
            }
            return MAPPER.readTree(in);
        }
    }

    private static Class<? extends RuntimeException> errorClassForSpecName(String name) {
        return switch (name) {
            case "DuplicateTupleError" -> DuplicateTupleError.class;
            case "InvalidFormatError" -> InvalidFormatError.class;
            case "EmptyRelationSetError" -> EmptyRelationSetError.class;
            default -> throw new IllegalArgumentException("Unknown spec error: " + name);
        };
    }

    private static void seed(InMemoryTupleStore store, JsonNode given) {
        for (JsonNode t : given) {
            store.createTuple(
                    t.get("subject_type").asText(),
                    t.get("subject_id").asText(),
                    t.get("relation").asText(),
                    t.get("object_type").asText(),
                    t.get("object_id").asText()
            );
        }
    }

    // ─── authorization.check (exact match) ───

    @TestFactory
    List<DynamicTest> checkConformance() throws IOException {
        JsonNode fixture = loadFixture("authorization/check.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode t : fixture.get("tests")) {
            String id = t.get("id").asText();
            String desc = t.get("description").asText();
            tests.add(DynamicTest.dynamicTest("[" + id + "] " + desc, () -> {
                InMemoryTupleStore store = new InMemoryTupleStore();
                seed(store, t.get("input").get("given_tuples"));
                JsonNode c = t.get("input").get("check");
                CheckResult result = store.check(
                        c.get("subject_type").asText(),
                        c.get("subject_id").asText(),
                        c.get("relation").asText(),
                        c.get("object_type").asText(),
                        c.get("object_id").asText()
                );
                JsonNode expected = t.get("expected").get("result");
                assertEquals(expected.get("allowed").asBoolean(), result.allowed());
            }));
        }
        return tests;
    }

    // ─── authorization.check_any (set form) ───

    @TestFactory
    List<DynamicTest> checkAnyConformance() throws IOException {
        JsonNode fixture = loadFixture("authorization/check-any.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode t : fixture.get("tests")) {
            String id = t.get("id").asText();
            String desc = t.get("description").asText();
            tests.add(DynamicTest.dynamicTest("[" + id + "] " + desc, () -> {
                InMemoryTupleStore store = new InMemoryTupleStore();
                seed(store, t.get("input").get("given_tuples"));
                JsonNode c = t.get("input").get("check");
                List<String> relations = new ArrayList<>();
                c.get("relations").forEach(r -> relations.add(r.asText()));
                JsonNode expected = t.get("expected");
                if (expected.has("error")) {
                    Class<? extends RuntimeException> ctor =
                            errorClassForSpecName(expected.get("error").asText());
                    assertThrows(ctor, () -> store.checkAny(
                            c.get("subject_type").asText(),
                            c.get("subject_id").asText(),
                            relations,
                            c.get("object_type").asText(),
                            c.get("object_id").asText()
                    ));
                } else {
                    CheckResult result = store.checkAny(
                            c.get("subject_type").asText(),
                            c.get("subject_id").asText(),
                            relations,
                            c.get("object_type").asText(),
                            c.get("object_id").asText()
                    );
                    assertEquals(expected.get("result").get("allowed").asBoolean(),
                            result.allowed());
                }
            }));
        }
        return tests;
    }

    // ─── authorization.create_tuple (uniqueness + format) ───

    private List<DynamicTest> createTupleConformance(String fixtureName) throws IOException {
        JsonNode fixture = loadFixture("authorization/" + fixtureName);
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode t : fixture.get("tests")) {
            String id = t.get("id").asText();
            String desc = t.get("description").asText();
            tests.add(DynamicTest.dynamicTest("[" + id + "] " + desc, () -> {
                InMemoryTupleStore store = new InMemoryTupleStore();
                seed(store, t.get("input").get("given_tuples"));
                JsonNode c = t.get("input").get("create");
                JsonNode expected = t.get("expected");
                if (expected.has("error")) {
                    Class<? extends RuntimeException> ctor =
                            errorClassForSpecName(expected.get("error").asText());
                    assertThrows(ctor, () -> store.createTuple(
                            c.get("subject_type").asText(),
                            c.get("subject_id").asText(),
                            c.get("relation").asText(),
                            c.get("object_type").asText(),
                            c.get("object_id").asText()
                    ));
                } else {
                    Tuple created = store.createTuple(
                            c.get("subject_type").asText(),
                            c.get("subject_id").asText(),
                            c.get("relation").asText(),
                            c.get("object_type").asText(),
                            c.get("object_id").asText()
                    );
                    assertTrue(created.id().startsWith("tup_"));
                }
            }));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> uniquenessConformance() throws IOException {
        return createTupleConformance("uniqueness.json");
    }

    @TestFactory
    List<DynamicTest> formatConformance() throws IOException {
        return createTupleConformance("format.json");
    }
}
