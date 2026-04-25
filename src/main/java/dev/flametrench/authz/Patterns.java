// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import java.util.regex.Pattern;

/**
 * Format-rule constants matching the Flametrench v0.1 specification.
 */
public final class Patterns {
    /** Relation name regex: {@code ^[a-z_]{2,32}$}. */
    public static final Pattern RELATION_NAME = Pattern.compile("^[a-z_]{2,32}$");

    /** Object-type prefix regex: {@code ^[a-z]{2,6}$}. Mirrors docs/ids.md. */
    public static final Pattern TYPE_PREFIX = Pattern.compile("^[a-z]{2,6}$");

    private Patterns() {
        // utility class
    }
}
