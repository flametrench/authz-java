# flametrench-authz (Java)

[![CI](https://github.com/flametrench/authz-java/actions/workflows/ci.yml/badge.svg)](https://github.com/flametrench/authz-java/actions/workflows/ci.yml)

Java SDK for the [Flametrench](https://github.com/flametrench/spec) authorization specification: relational tuples and exact-match `check()`. Exact-match is the default — no implicit rewriting at the API boundary ([ADR 0001](https://github.com/flametrench/spec/blob/main/decisions/0001-authorization-model.md)). v0.2 adds opt-in rewrite rules ([ADR 0007](https://github.com/flametrench/spec/blob/main/decisions/0007-rewrite-rules.md)) — `computed_userset` (role implication) and `tuple_to_userset` (parent-child inheritance) — for adopters who want hierarchies. Group expansion remains deferred.

The same fixture corpus that gates `@flametrench/authz` (Node), `flametrench/authz` (PHP), and `flametrench-authz` (Python) runs here.

**Status:** v0.2.0 (stable). Includes `ShareStore` ([ADR 0012](https://github.com/flametrench/spec/blob/main/decisions/0012-share-tokens.md)) and Postgres-backed adapters (`PostgresTupleStore`, `PostgresShareStore`). Per [ADR 0013](https://github.com/flametrench/spec/blob/main/decisions/0013-postgres-adapter-transaction-nesting.md) the Postgres adapters cooperate with adopter-side outer transactions via savepoints when constructed with a caller-owned `Connection`.

```java
import dev.flametrench.authz.InMemoryTupleStore;
import dev.flametrench.authz.CheckResult;
import dev.flametrench.ids.Id;

InMemoryTupleStore store = new InMemoryTupleStore();
String alice = Id.generate("usr");
String project42 = Id.generate("org").substring(4);

store.createTuple("usr", alice, "editor", "proj", project42);

CheckResult result = store.check("usr", alice, "editor", "proj", project42);
assert result.allowed();
```

## Installation

Maven:

```xml
<dependency>
    <groupId>dev.flametrench</groupId>
    <artifactId>authz</artifactId>
    <version>0.2.0</version>
</dependency>
```

Requires Java 17+. Depends on `dev.flametrench:ids` for `tup_` id generation.

## Spec invariants enforced

- **Exact-match `check()`** — returns true iff a tuple with the exact 5-tuple natural key exists. No derivation; admin does NOT imply editor.
- **Uniqueness** — duplicate creation of the same `(subjectType, subjectId, relation, objectType, objectId)` raises `DuplicateTupleError`.
- **Format** — relations match `^[a-z_]{2,32}$`; object types match `^[a-z]{2,6}$`. Violations raise `InvalidFormatError`.
- **Empty-set rejection** — `checkAny()` with an empty relations list raises `EmptyRelationSetError`.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Copyright 2026 NDC Digital, LLC.
