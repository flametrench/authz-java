// Copyright 2026 NDC Digital, LLC
// SPDX-License-Identifier: Apache-2.0

package dev.flametrench.authz;

import dev.flametrench.ids.Id;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reference in-memory ShareStore. O(1) verify via secondary token-hash
 * index; deterministic for tests.
 *
 * <p>Token storage matches the Postgres reference (SHA-256 → 32 raw
 * bytes, constant-time compare on verify), so behavior is byte-
 * identical across backends.
 */
public class InMemoryShareStore implements ShareStore {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final Map<String, Share> shares = new LinkedHashMap<>();
    /** share_id → raw token hash bytes. */
    private final Map<String, byte[]> tokenHashes = new HashMap<>();
    /** Hex-encoded token hash → share_id; holds shares in every state. */
    private final Map<String, String> byTokenHash = new HashMap<>();
    private final Clock clock;

    public InMemoryShareStore() {
        this(Clock.systemUTC());
    }

    public InMemoryShareStore(Clock clock) {
        this.clock = clock;
    }

    private Instant now() {
        return clock.instant();
    }

    private static byte[] hashToken(String token) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(token.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String generateToken() {
        byte[] raw = new byte[32];
        SECURE_RANDOM.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static void validate(String relation, String objectType, long expiresInSeconds) {
        if (!Patterns.RELATION_NAME.matcher(relation).matches()) {
            throw new InvalidFormatError(
                    "relation '" + relation + "' must match " + Patterns.RELATION_NAME.pattern(),
                    "relation"
            );
        }
        if (!Patterns.TYPE_PREFIX.matcher(objectType).matches()) {
            throw new InvalidFormatError(
                    "objectType '" + objectType + "' must match " + Patterns.TYPE_PREFIX.pattern(),
                    "object_type"
            );
        }
        if (expiresInSeconds <= 0) {
            throw new InvalidFormatError(
                    "expiresInSeconds must be positive, got " + expiresInSeconds,
                    "expires_in_seconds"
            );
        }
        if (expiresInSeconds > MAX_TTL_SECONDS) {
            throw new InvalidFormatError(
                    "expiresInSeconds exceeds the spec ceiling of "
                  + MAX_TTL_SECONDS + " (365 days)",
                    "expires_in_seconds"
            );
        }
    }

    @Override
    public CreateShareResult createShare(
            String objectType,
            String objectId,
            String relation,
            String createdBy,
            long expiresInSeconds,
            boolean singleUse
    ) {
        validate(relation, objectType, expiresInSeconds);
        Instant now = now();
        Instant expiresAt = now.plusSeconds(expiresInSeconds);
        String shareId = Id.generate("shr");
        String token = generateToken();
        byte[] tokenHash = hashToken(token);
        Share share = new Share(
                shareId, objectType, objectId, relation, createdBy,
                expiresAt, singleUse, null, null, now
        );
        shares.put(shareId, share);
        tokenHashes.put(shareId, tokenHash);
        byTokenHash.put(hex(tokenHash), shareId);
        return new CreateShareResult(share, token);
    }

    @Override
    public Share getShare(String shareId) {
        Share s = shares.get(shareId);
        if (s == null) throw new ShareNotFoundError("Share " + shareId + " not found");
        return s;
    }

    @Override
    public VerifiedShare verifyShareToken(String token) {
        byte[] inputHash = hashToken(token);
        String shareId = byTokenHash.get(hex(inputHash));
        if (shareId == null) throw new InvalidShareTokenError();
        Share share = shares.get(shareId);
        byte[] storedHash = tokenHashes.get(shareId);
        if (share == null || storedHash == null) throw new InvalidShareTokenError();
        // Defense-in-depth: constant-time compare even though the index just hit.
        if (!constantTimeEquals(inputHash, storedHash)) {
            throw new InvalidShareTokenError();
        }
        // Spec error precedence: revoked > consumed > expired.
        if (share.revokedAt() != null) throw new ShareRevokedError();
        if (share.singleUse() && share.consumedAt() != null) {
            throw new ShareConsumedError();
        }
        Instant now = now();
        if (!now.isBefore(share.expiresAt())) {
            throw new ShareExpiredError();
        }
        if (share.singleUse()) {
            // Atomic consume — set consumedAt on the public record. Keep
            // the byTokenHash entry so a second verify can find the row
            // and return ShareConsumedError (not InvalidShareTokenError).
            // The Postgres equivalent is UPDATE ... WHERE consumed_at IS
            // NULL RETURNING ...
            Share consumed = new Share(
                    share.id(), share.objectType(), share.objectId(),
                    share.relation(), share.createdBy(), share.expiresAt(),
                    share.singleUse(), now, share.revokedAt(), share.createdAt()
            );
            shares.put(shareId, consumed);
        }
        return new VerifiedShare(shareId, share.objectType(), share.objectId(), share.relation());
    }

    @Override
    public Share revokeShare(String shareId) {
        Share share = shares.get(shareId);
        if (share == null) throw new ShareNotFoundError("Share " + shareId + " not found");
        if (share.revokedAt() != null) {
            // Idempotent: return the existing record with the original timestamp.
            return share;
        }
        Share revoked = new Share(
                share.id(), share.objectType(), share.objectId(),
                share.relation(), share.createdBy(), share.expiresAt(),
                share.singleUse(), share.consumedAt(), now(), share.createdAt()
        );
        shares.put(shareId, revoked);
        // Don't drop the byTokenHash entry — verify must find the row to
        // return ShareRevokedError, not InvalidShareTokenError.
        return revoked;
    }

    @Override
    public Page<Share> listSharesForObject(
            String objectType,
            String objectId,
            String cursor,
            int limit
    ) {
        int cap = Math.min(limit, 200);
        List<Share> matching = new ArrayList<>();
        for (Share s : shares.values()) {
            if (!s.objectType().equals(objectType)) continue;
            if (!s.objectId().equals(objectId)) continue;
            if (cursor != null && s.id().compareTo(cursor) <= 0) continue;
            matching.add(s);
        }
        matching.sort(Comparator.comparing(Share::id));
        List<Share> data = matching.subList(0, Math.min(cap, matching.size()));
        String nextCursor = matching.size() > cap && !data.isEmpty()
                ? data.get(data.size() - 1).id()
                : null;
        return new Page<>(List.copyOf(data), nextCursor);
    }
}
