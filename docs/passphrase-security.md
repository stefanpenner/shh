# Security audit — passphrase ("brain") keys

Scope: `IdentityFromPassphrase` (argon2id → X25519), the Bech32 encoder, and the
`shh users add --passphrase` / `shh login --passphrase` flows.

## Design

A passphrase is run through **argon2id** with a **fixed public salt** to produce
32 bytes, used as an X25519 seed → a normal age key. The key is therefore an
ordinary `age1…` recipient / `AGE-SECRET-KEY-1…` identity; the rest of shh treats
it like any other key. Nothing is stored — recovery re-derives from the
passphrase alone.

```
passphrase ──argon2id(salt=sha256("shh-brainkey-v1"), m=256MiB, t=3, p=4)──▶ 32B
          ──bech32──▶ AGE-SECRET-KEY-1…  ──age──▶ age1…(recipient)
```

## Threat model

`.env.enc` is **committed** (often to a shared/remote git). Assume the attacker
has the full file: the public recipient `age1…` and the wrapped data key. The
recipient is a free **offline oracle** — `guess → argon2id → derive recipient →
compare` — so security reduces to **passphrase entropy × argon2 cost**. Nothing
else (salt secrecy, file access control) can be relied on.

## Findings

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | **KDF** argon2id m=256MiB/t=3/p=4 — memory-hard, GPU/ASIC-resistant, above OWASP floors. Fixed forever (changing breaks existing keys). | — | Sound |
| 2 | **Fixed public salt** → deterministic: same passphrase = same key everywhere. No per-project uniqueness; reusing a phrase across projects links the recipients. Accepted: it's what makes recovery pure-memory. argon2 memory-hardness defeats rainbow tables regardless. | Low | Accepted, documented |
| 3 | **Offline brute-force is the real risk.** Weak/human-chosen passphrase = crackable. Tool *warns* but cannot enforce. | High (user-dependent) | Mitigated by mandate; entropy guard = TODO |
| 4 | **Extractable-class.** Shows `[extractable]`; if the passphrase leaks it's a copyable secret → the rotation-on-leak rule applies (change values, not just remove). | Med | Documented (README) |
| 5 | **No passphrase via argv/env.** Both flags are booleans that *prompt*; phrase never in shell history / `ps` / CI logs. No-echo via `term.ReadPassword`. Only the derived key (never the phrase) is stored. | — | Good |
| 6 | **Typo lockout.** A brain key is unrecoverable; a typo on enrollment = a dead recipient. Mitigated by confirm-twice on add. | Med | Mitigated; rehearse the phrase |
| 7 | **Memory hygiene.** Go strings/slices for the phrase & seed aren't zeroed (immutable strings); a memory/swap dump during use could recover them. Inherent to Go. | Low | Noted; mlock/zeroing = future |
| 8 | **Custom Bech32 encoder.** Serialization only — no secret-dependent branching, no comparison/timing channel. Cross-validated against age's decoder over 256 random seeds + BIP-173 known-answer. | Low | Tested |
| 9 | **Seed → X25519.** Any 32 bytes is a valid scalar after X25519 clamping (done by age); no bias/validity concern. argon2 via vetted `x/crypto`. | — | Sound |
| 10 | **No downgrade surface.** Derived key is a plain X25519; nothing flags it as passphrase-derived, so there's only one (strong) path — no weaker mode to force. | — | Sound |

## Recommendations

1. **Generated high-entropy passphrase only** — 8-word diceware (~103 bits). A
   6-word (~77 bit) phrase is the practical floor with this KDF.
2. **Complementary, not sole** — pair with a hardware key; a brain key's failure
   modes (forgetting, offline grind) are uncorrelated with hardware's.
3. **Rehearse it** on a schedule — an un-rehearsed failsafe is the one that fails.
4. Future hardening: an entropy/length guard at enrollment; zero the seed buffer;
   optionally raise argon2 memory if only a workstation derives it.

## Bottom line

The cryptography and plumbing are sound. The residual risk is **entirely the
human passphrase**: with a generated high-entropy phrase it's a strong
last-resort failsafe; with a guessable one, the committed file makes it
brute-forceable. Treat it as extractable, keep it complementary, rehearse it.
