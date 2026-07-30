# Security Audit — shh v0.7.0

> Adversarial multi-agent audit (6 attack dimensions → 2 skeptics per finding →
> synthesis). 5 of 6 findings survived verification.

## 1. Verdict

shh v0.7.0's core cryptographic construction is sound: the data-key wrapping, the
v2 MAC-before-trust discipline in `ReWrapDataKey`/`DecryptSecrets`, the argon2id
"brain key" parameters, and the encoding-only `Validate*` helpers are all
well-reasoned and correctly implemented. The one genuinely serious problem is a
**plugin-execution gap**: recipient strings read from the committed,
attacker-controllable `.env.enc` flow into `crypto.ParseRecipient()`, which shells
out to an `age-plugin-<name>` binary on `PATH` — and on the `shh encrypt` path
this happens with **no MAC verification at all**. Given the threat model
(`.env.enc` is public and PR-modifiable; shh runs on dev machines and CI), this is
a credible local-code-execution primitive when chained with any way to land a
binary on `PATH`. The remaining findings are a usability/lockout footgun
(whitespace) and accepted-by-design trade-offs (no entropy floor, fixed salt).

## 2. Confirmed issues

| Severity | Title | Location | One-line fix |
|---|---|---|---|
| **High** | Untrusted recipients from `.env.enc` reach `ParseRecipient` → plugin binary exec | `crypto/wrap.go:13`; `crypto/recipients.go:35-41`; reached unverified via `cli/commands.go:54-60` | `ValidateRecipient` (encoding-only) every recipient at `encfile` load, before any `Wrap`/`ParseRecipient`. |
| Medium | Passphrase whitespace not normalized → permanent brain-key lockout | `cli/auth.go:36-52`; `crypto/passphrase.go:32-39` | `TrimSpace` the passphrase once, consistently, before the KDF. |
| Low | No entropy floor at passphrase enrollment | `cli/auth.go:36-67` | Enforce a minimum length / reject weak phrases (currently warn-only). |
| Info | Fixed argon2 salt links identical passphrases across projects | `crypto/passphrase.go:22,38` | Accepted trade-off; document, recommend per-project phrases or hardware keys. |

## 3. Per-issue detail

### High — Untrusted plugin execution via recipients in `.env.enc`

`WrapDataKeyForRecipient` (`wrap.go:13`) calls `ParseRecipient` on every recipient
string. For a plugin-format recipient (`age1<name>1…`), `ParseRecipient` calls
`plugin.NewRecipient`, which the age library implements by `exec`-ing
`age-plugin-<name>` from `PATH`.

Recipients are parsed out of `.env.enc` and stored at load time **with no
validation**. The MAC-before-trust gate in `DecryptSecrets`/`ReWrapDataKey`
(`secrets.go:122,152`) covers `set`/`edit`/`rm`/`users add`/`remove` — but:

- **`shh encrypt` (`commands.go:54-60`)** reuses an existing file's recipients and
  re-encrypts **without ever decrypting it**, so the MAC is never checked before
  the plugin binary is exec'd. An attacker editing the committed `.env.enc`
  controls the recipient names here.
- Even on MAC-verified paths, the MAC only proves *some* authorized key signed the
  recipient set — it does not stop a malicious plugin recipient merged via PR and
  then re-wrapped for everyone.

**Exploit.** Attacker PRs a recipient `"x" = "age1evil1q…"` and lands
`age-plugin-evil` on a victim's `PATH` (malicious dep postinstall, committed
`./bin`, CI image). Victim runs `shh encrypt` → `age-plugin-evil` executes →
arbitrary code with their privileges. High (not Critical): needs a binary on
`PATH`, and secret confidentiality/MAC integrity is not itself broken.

**Fix.** Apply the existing encoding-only `crypto.ValidateRecipient` to every
recipient at `encfile` load/normalize, before any `Wrap`. Optionally: an
allowlist of plugin names and/or stop `cmdEncrypt` acting on an unverified file.

### Medium — Passphrase whitespace not normalized

`readNewPassphrase` (`auth.go:36-52`) checks the *trimmed* phrase is non-empty but
returns the raw `p1`; `IdentityFromPassphrase` (`passphrase.go:32-39`) trims only
for the empty-check, then feeds **untrimmed** bytes to argon2. A stray trailing
space at enrollment derives a different key than a clean login types → since the
brain key is a nothing-stored failsafe, the lockout is **permanent**.

**Fix.** `TrimSpace` once before the KDF so enrollment and login always agree.

### Low — No entropy enforcement at enrollment

`passphraseRecipient` warns but enforces nothing. argon2id at 256 MiB/t=3/p=4 is
strongly memory-hard, so a weak phrase falls slowly rather than instantly — but
`.env.enc` is public, so a floor (min length / weak-phrase rejection) is worth
adding. Documented as "entropy guard = TODO".

### Info — Fixed argon2 salt links passphrases across projects

Constant salt `"shh-brainkey-v1"` → identical passphrases derive identical
recipients everywhere; an attacker comparing two committed files can infer reuse.
**Intentional** (it's what makes recovery pure-memory). Recommend per-project
phrases or hardware keys where unlinkability matters.

## 4. Checked and found SOLID

- **MAC-before-trust** on sensitive paths (`secrets.go:115-124,139-154`),
  constant-time `hmac.Equal` — `users add`/`remove` can't be tricked into
  re-wrapping an attacker-chosen data key.
- **Data-key wrap/unwrap** — base64 + age + 32-byte invariant (`wrap.go:43-63`);
  coherent v1/v2 MAC split.
- **Plugin trial-unwrap fallback** (`resolveDataKey`, `secrets.go:67-112`) — fast
  path when derivable, trial only for plugin identities; MAC still enforced after.
- **Encoding-only validators** correctly avoid invoking any binary — the only gap
  is they aren't applied to file-loaded recipients (the High finding).
- **argon2id parameters** — 256 MiB/t=3/p=4, "never change" contract + v2 note.
- **Identity hygiene** — no-echo `term.ReadPassword`, never persisted (re-derived),
  child-env scrubbing of `SHH_AGE_KEY`/`SHH_PLAINTEXT`, dangerous env-var rejection.
- **bech32/brain-key encoding** round-trips through `age.ParseX25519Identity`, so a
  malformed encoding fails loudly rather than producing a silently-wrong key.

**Bottom line:** one High hardening gap (validate file-loaded recipients before
they can trigger plugin exec; stop `shh encrypt` acting on an unverified file), one
Medium lockout fix (normalize passphrase whitespace), two accepted/low items. The
cryptographic core is well-built.
