-- Minimal idempotent tup schema for authz conformance tests.
-- Drops and recreates tup; creates usr IF NOT EXISTS (needed for FK).
-- Apply once per @TestFactory group; TRUNCATE between test cases.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS usr (
    id         UUID PRIMARY KEY,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

DROP TABLE IF EXISTS tup CASCADE;

CREATE TABLE tup (
    id            UUID PRIMARY KEY,
    subject_type  TEXT NOT NULL,
    subject_id    UUID NOT NULL,
    relation      TEXT NOT NULL
                    CHECK (relation ~ '^[a-z_]{2,32}$'),
    object_type   TEXT NOT NULL
                    CHECK (object_type ~ '^[a-z]{2,6}$'),
    object_id     UUID NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    UUID,
    UNIQUE (subject_type, subject_id, relation, object_type, object_id)
);

CREATE INDEX tup_object_relation_idx ON tup (object_type, object_id, relation);
CREATE INDEX tup_subject_idx         ON tup (subject_type, subject_id);
