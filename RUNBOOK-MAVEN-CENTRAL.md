# Maven Central Publishing Runbook

This document describes how to publish `dev.flametrench:authz` to Maven Central. The same flow applies to `dev.flametrench:{ids,identity,tenancy}` — each is a sibling repo with the same `release` profile in its `pom.xml`.

For cross-ecosystem release process (per-package CHANGELOG, doc-surface sync, post-publish verification, the "stable" gating bar that applies regardless of language), see [`spec/docs/release-checklist.md`](https://github.com/flametrench/spec/blob/main/docs/release-checklist.md). The Maven Central flow below covers the Java-specific publishing mechanics; the spec checklist covers the broader release discipline.

The pom's `release` profile wires four plugins: `maven-source-plugin` (sources jar), `maven-javadoc-plugin` (javadoc jar), `maven-gpg-plugin` (artifact signing), and `central-publishing-maven-plugin` (Sonatype Central Portal upload). Local dev builds don't activate the profile, so day-to-day work doesn't need GPG or a network round-trip.

## One-time setup

### 1. Sonatype Central Portal account

1. Sign in at https://central.sonatype.com.
2. Add the namespace `dev.flametrench`. The portal will provide a verification TXT record, e.g.:
   ```
   _sonatype.flametrench.dev    TXT    "<verification-token>"
   ```
3. Add the TXT record at the DNS provider for `flametrench.dev`. Verification typically completes within a few minutes once DNS propagates; namespace approval by Sonatype follows in 1–2 business days.

### 2. Generate a GPG signing key

Maven Central requires every artifact to be GPG-signed. The signing identity binds to the email used in the pom's `<developers>` block (`nate@site-source.com` for these packages).

```
gpg --full-generate-key
```

Choose:
- Key kind: `(1) RSA and RSA`
- Key size: `4096`
- Expiry: `0` (never) or `2y` if you'd rather rotate.
- Name: `Nathan Call`
- Email: `nate@site-source.com`
- Comment: leave blank
- Passphrase: pick a strong one and put it in your password manager.

Capture the long key ID for the next step:

```
gpg --list-secret-keys --keyid-format LONG nate@site-source.com
```

The output's `sec   rsa4096/<KEY_ID>` line is the long key ID.

### 3. Publish the public key to keyservers

Sonatype validates signatures by fetching the public key from public keyservers. Push to two for redundancy — different consumers query different ones:

```
KEY_ID=<paste from previous step>
gpg --keyserver keys.openpgp.org    --send-keys "$KEY_ID"
gpg --keyserver keyserver.ubuntu.com --send-keys "$KEY_ID"
```

Note: `keys.openpgp.org` requires email confirmation before the key becomes searchable by email — watch `nate@site-source.com` for the verification message.

### 4. Generate a Central Portal user token

1. At https://central.sonatype.com, go to **Account → Generate User Token**.
2. Copy the username + password values shown (they are NOT your portal login credentials — they're a derived token pair).

### 5. Configure `~/.m2/settings.xml`

Add (or merge into) the `<servers>` section:

```xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <servers>
    <server>
      <id>central</id>
      <username>YOUR_USER_TOKEN_NAME</username>
      <password>YOUR_USER_TOKEN_PASSWORD</password>
    </server>
  </servers>
</settings>
```

The `<id>central</id>` value MUST match `<publishingServerId>central</publishingServerId>` in the pom's release profile.

### 6. Export GPG passphrase

The `maven-gpg-plugin` is configured for the `loopback` pinentry mode, which expects the passphrase via env var:

```
export MAVEN_GPG_PASSPHRASE=...your gpg passphrase...
```

For shells that source `~/.zshenv` or similar on each invocation, add it there if you want it persisted. Otherwise export per-session before each publish.

## Publish

For a single artifact:

```
cd <repo-dir>
mvn -B clean deploy -P release
```

The release profile builds the main jar, sources jar, and javadoc jar; signs all three plus the pom with GPG; uploads the bundle to Sonatype Central Portal; and waits for the validation phase to complete. With `<autoPublish>false</autoPublish>` (the default in this pom), the bundle stays in **PENDING** state on the portal — you manually click **Publish** at https://central.sonatype.com/publishing/deployments to release it to Maven Central. The artifact is searchable on Central within ~30 minutes of release; some downstream mirrors take up to 4 hours.

To enable hands-off publishing later, change the pom's release profile to `<autoPublish>true</autoPublish>`.

## Publishing all four

Once one publish succeeds end-to-end, the same flow works for the rest:

```
for d in ids-java authz-java tenancy-java identity-java; do
  ( cd ~/flametrench-setup/$d && mvn -B clean deploy -P release ) || break
done
```

## Troubleshooting

- **`gpg: signing failed: Inappropriate ioctl for device`** — the loopback pinentry needs the passphrase in `MAVEN_GPG_PASSPHRASE`. Confirm the env var is exported in the same shell that runs `mvn`.
- **`401 Unauthorized` on upload** — `~/.m2/settings.xml` `<id>` doesn't match `central`, or the user token is wrong / regenerated.
- **`Public key not found`** — Sonatype couldn't fetch your key. Wait a few minutes after the keyserver push; key propagation isn't instant. Re-send to a second keyserver.
- **`Namespace dev.flametrench has not been verified`** — DNS TXT record propagation hasn't completed yet, or the portal hasn't picked it up. The portal has a "Re-check" button on the namespace page.
- **Bundle stuck in `VALIDATING` for >10 minutes** — refresh the portal; if it remains stuck, the bundle has a validation error that the portal lists in the deployment details. Common causes: missing `<developers>`, missing sources/javadoc jars, signature mismatch.

## Why we use a `release` profile

Local dev builds (`mvn test`, IDE imports, CI test runs) don't need GPG, don't need the Sonatype upload, and don't need to generate Javadoc — those are slow / network-bound / require credentials that not every contributor has. Wrapping all four publishing plugins in a profile keeps day-to-day Maven invocations fast and contributor-friendly while making release cuts a single explicit `-P release` opt-in.
