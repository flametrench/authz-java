// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import java.util.List;

/**
 * Paginated result envelope. {@code nextCursor} is null when no more
 * pages are available.
 */
public record Page<T>(List<T> data, String nextCursor) {
}
