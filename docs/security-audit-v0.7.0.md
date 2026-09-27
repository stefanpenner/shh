# Security audit record for shh v0.7.0

This file records the v0.7.0 audit. It is not a description of the current tree.

## Result

In that audit, the data-key wrap was sound. The MAC check before a re-wrap was sound. The argon2id parameters were sound. One high gap remained. A recipient string from `.env.enc` could cause age to start a plugin program.

## Findings in v0.7.0

| Severity | Finding | Fix named in that audit |
| --- | --- | --- |
| High | An untrusted plugin recipient could reach program start. `shh encrypt` could do this with no MAC check. | Check recipient encoding at load, before wrap. |
| Medium | Passphrase space was not normalized. Enrollment and login could derive different keys. | Trim the phrase once, before the KDF. |
| Low | Enrollment did not enforce phrase entropy. | Reject a weak phrase. The audit left this as future work. |
| Info | The argon2 salt is a fixed public label. The same phrase matches across projects. | Accepted. Document it. |

## Checked and sound in v0.7.0

- The MAC check ran before `users add` and `users remove` trusted the data key.
- The MAC compare used `hmac.Equal`.
- Unwrap required a 32-byte data key.
- Plugin trial unwrap still checked the MAC afterward.
- The encoding checks did not start a plugin program. The gap was that load did not call them.
- argon2id was 256 MiB, time 3, and 4 threads.
- The passphrase prompt did not echo. The phrase was not stored.
- Child processes did not receive `SHH_AGE_KEY` or `SHH_PLAINTEXT`.
- A bad Bech32 string failed in the age parser.

## Current code

These later facts are not part of the v0.7.0 record. They describe the tree after that audit.

- An unknown plugin name does not start a program. Wrap of `yubikey` or `se` does start `age-plugin-<name>` from `PATH`.
- `shh encrypt` decrypts the old vault before it reuses recipients.
- Enrollment and login trim the phrase the same way. Enrollment rejects a phrase shorter than 12 characters.
- The salt label is still `shh-brainkey-v1`.
