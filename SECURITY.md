# Security Design

This document explains the security architecture of `shh`: the encrypted file format, cryptographic choices, trust model, and what the system does and does not protect against.

## Encrypted File Format (`.env.enc`)

The `.env.enc` file is plain TOML with five fields:

```toml
version = 1
mac = "513417edad3bfd08..."
data_key = "YWdlLWVuY3J5cHRpb24..."

[recipients]
"https://github.com/alice" = "age1abc..."

[secrets]
API_KEY = "EU8FFxADNGlY..."
```

### `version`

**What:** Integer format version (currently `1`).

**Why:** Allows future changes to the file format, encryption scheme, or MAC construction without silently misinterpreting old files. On load, `shh` rejects any version it doesn't understand.

### `mac`

**What:** Hex-encoded HMAC-SHA256 digest.

**Why:** Detects tampering with any part of the file. The MAC covers every field — version, data key, recipients (names and public keys), and all secret entries (names and ciphertext). An attacker who modifies any byte causes MAC verification to fail.

**How:** Computed with HMAC-SHA256, keyed by the data key itself. Fields are fed in deterministic sorted order with null-byte separators to prevent ambiguity between adjacent values. Verified using `hmac.Equal()` (constant-time comparison) to prevent timing side-channels.

**What it prevents:**
- Adding, removing, or modifying recipients without detection
- Altering encrypted secret values or key names
- Changing the version or wrapped data key
- Downgrade attacks (changing version to exploit a hypothetical older parser)

**Circular protection:** An attacker cannot recompute the MAC because the MAC key (the data key) is itself encrypted under age — only authorized recipients can unwrap it.

### `data_key`

**What:** Base64-encoded age-encrypted blob containing a random 32-byte AES-256 key.

**Why:** Envelope encryption. A single symmetric key encrypts all secrets, and that key is wrapped with age (X25519 HPKE) for every recipient. This means:

- Adding a user re-wraps the data key for the expanded recipient list — existing secret ciphertext doesn't change.
- Removing a user generates a **new** data key, re-encrypts all secrets, and wraps only for remaining recipients. The removed user's knowledge of the old data key becomes useless.

**How:** The 32-byte key is generated from `crypto/rand`. It's encrypted with `filippo.io/age` to all recipient public keys, then base64-encoded. On decryption, the user's private age identity (stored in the OS keyring) unwraps it.

**Key rotation:** The data key is rotated on every `users remove` operation. On `users add`, the same data key is re-wrapped to include the new recipient (no re-encryption of secrets needed since the new user is being granted access to the current secrets).

### `[recipients]`

**What:** A TOML table mapping human-readable names to age public keys (`age1...`).

**Why:** Defines who can decrypt. Each entry is a name (typically `https://github.com/<username>`) paired with an age X25519 public key (validated against `^age1[a-z0-9]{58}$`).

**How recipients are added:**
1. `shh users add alice` fetches `https://github.com/alice.keys` over HTTPS
2. Finds the first `ssh-ed25519` public key
3. Converts it to an age public key via `ssh-to-age`
4. Stores the mapping in this section and re-wraps the data key

**Access control:** During decryption, `shh` checks that the user's public key appears in this map before attempting to unwrap the data key. This is a fast-fail check — the real cryptographic enforcement is that age will refuse to decrypt for a key that wasn't in the recipient list during encryption.

**What's visible:** Recipient names and public keys are **not encrypted**. Anyone with access to the file can see who has access. This is intentional — it enables `shh users list` without requiring decryption and allows teams to audit access via code review.

### `[secrets]`

**What:** A TOML table mapping environment variable names to base64-encoded AES-256-GCM ciphertext.

**Why:** Each secret is encrypted independently so that the file format remains a simple key-value map. Secret **names are visible** (they're TOML keys); only **values are encrypted**.

**How each value is encrypted:**
1. A fresh 12-byte random nonce is generated from `crypto/rand`
2. The plaintext is encrypted with AES-256-GCM using the data key
3. The secret's key name (e.g., `API_KEY`) is passed as Additional Authenticated Data (AAD)
4. The output is `nonce || ciphertext || GCM-tag`, base64-encoded

**Why AAD matters:** The key name bound as AAD means an attacker cannot swap encrypted values between different keys. Moving the ciphertext from `API_KEY` to `DB_PASSWORD` causes GCM authentication to fail because the AAD won't match.

**Why names are plaintext:** This is a deliberate tradeoff. Visible names let teams see which secrets exist, diff changes in code review, and detect missing configuration — without needing to decrypt. If secret names are themselves sensitive, this is a known limitation.

## Cryptographic Primitives

| Purpose | Algorithm | Why |
|---------|-----------|-----|
| Per-value encryption | AES-256-GCM | Authenticated encryption; GCM provides confidentiality + integrity + AAD support |
| Key wrapping | age (X25519 HPKE) | Modern, audited, multi-recipient asymmetric encryption |
| File integrity | HMAC-SHA256 | Keyed hash covers all fields; prevents tampering |
| Key generation | `crypto/rand` | OS-level CSPRNG; 32 bytes for AES key, 12 bytes per nonce |
| MAC comparison | `hmac.Equal()` | Constant-time; prevents timing attacks |
| Key storage | OS keyring | macOS Keychain, GNOME Secret Service, Windows Credential Manager |

## Trust Model

`shh` trusts the following:

1. **GitHub as an identity provider.** When you run `shh users add alice`, you trust that `github.com/alice.keys` returns Alice's real SSH public key. If Alice's GitHub account is compromised, the attacker's key gets added instead.

2. **The OS keyring.** Private age keys are stored in the system keyring (macOS Keychain, etc.), protected by the OS's access controls and the user's login credentials.

3. **Repository access controls.** Anyone who can push to the repo can modify `.env.enc`. Git history provides an audit trail of changes, but `shh` itself does not enforce who may add or remove recipients — that's the repository's job.

4. **The local machine.** Decrypted secrets exist in memory (and briefly in a temp file during `shh edit`). `shh` sets file permissions to `0600` and cleans up temp files, but cannot protect against a compromised OS, malware with keyring access, or physical memory inspection.

## What shh Protects Against

| Threat | Defense |
|--------|---------|
| Unauthorized decryption | Only recipients listed in the file can unwrap the data key |
| File tampering (any field) | HMAC-SHA256 verification fails |
| Swapping encrypted values between keys | GCM AAD (key name) causes authentication failure |
| Removed user accessing new secrets | Full data key rotation on removal; old key cannot unwrap new data key |
| Privilege escalation via env vars | Denylist blocks `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, etc. |
| Shell injection via secret values | `shellQuote()` uses POSIX single-quoting; no shell expansion possible |
| MITM on GitHub key fetch | HTTPS-only; redirects restricted to `github.com`; 30s timeout; 1MB response limit |
| Timing attacks on MAC verification | `hmac.Equal()` (constant-time) |
| Partial file writes / corruption | Atomic write (temp file + rename); `0600` permissions |

## What shh Does NOT Protect Against

| Threat | Why |
|--------|-----|
| Compromised GitHub account | `shh` trusts GitHub as the source of SSH public keys |
| Secrets the removed user already saw | Removal rotates the key, but the user had legitimate access before removal |
| Secret names being confidential | Key names are stored in plaintext (intentional design tradeoff) |
| `shh set KEY value` visible in `ps` | Command-line arguments are visible to other processes on the same machine; use `shh edit` for sensitive values |
| SIGKILL during `shh edit` | Temp file cleanup runs on SIGINT/SIGTERM but not SIGKILL; file has `0600` permissions as mitigation |
| Memory forensics | Decrypted secrets are Go strings in GC-managed memory; not explicitly zeroed |
| Concurrent writes | No file locking; last writer wins (git merge conflicts surface this) |

## Tricky Scenarios

**Removed user has old `.env.enc` from git history.**
They can decrypt the old version (they were authorized then) but not the current one. The data key was rotated on removal and all secrets re-encrypted.

**Attacker edits `.env.enc` to add themselves as a recipient.**
MAC verification fails on next decrypt. The attacker cannot recompute the MAC because the MAC key is the data key, which they can't unwrap without already being a recipient.

**Two people run `shh set` at the same time.**
Last writer wins. The second write overwrites the first. Git will show a merge conflict if both are committed, surfacing the issue.

**Secret value contains `$(command)` or backticks.**
Safe. `shh env` wraps values in POSIX single quotes (`'...'`), which prevent all shell expansion. The value is stored and returned literally.

**User adds the same person twice under different names.**
Duplicate public key check prevents this. `shh` rejects the addition with "User already present."

**`SHH_AGE_KEY` is set in CI and echoes to logs.**
The key is compromised. `shh` filters `SHH_AGE_KEY` from child processes (editor, shell) but cannot control the parent CI environment. Mark it as a masked/secret variable in your CI system.

## File Write Safety

Encrypted files are written atomically:
1. Content is written to a temp file (`.shh-*.tmp`) in the same directory
2. Permissions are set to `0600` before the file is closed
3. The temp file is renamed over the target (atomic on POSIX)
4. On any error, the temp file is removed (best-effort cleanup)

This prevents partial writes from corrupting the encrypted file.

## Network Security

GitHub SSH key fetches use a hardened HTTP client:
- HTTPS only (rejects `http://` redirects)
- Redirects only to `github.com` (rejects other hosts)
- Maximum 3 redirects
- 30-second timeout
- 1MB response size limit
- No authentication required (GitHub's public key endpoint is intentionally public)

## Input Validation

| Input | Pattern | Rejects |
|-------|---------|---------|
| Age public keys | `^age1[a-z0-9]{58}$` | Malformed keys, injection attempts |
| GitHub usernames | `^[a-zA-Z0-9]([a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$` | Path traversal, special characters |
| Env var names | `^[A-Za-z_][A-Za-z0-9_]*$` | Shell metacharacters, empty names |
| TOML values | No control characters (0x00–0x1F except tab/newline) | TOML injection, null bytes |
| Dangerous env vars | Denylist: `PATH`, `HOME`, `SHELL`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, etc. | Privilege escalation via env |
