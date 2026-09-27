# Security

shh encrypts values in `.env.enc`. You can commit that file. shh does not prove who wrote it. Git review is that control.

## Terms

| Term | Meaning |
| --- | --- |
| Vault | The file `.env.enc`. |
| Data key | The 32-byte AES key inside the vault. |
| Recipient | An age public key that can open the data key. |
| MAC | HMAC-SHA256 over the vault fields. The key is the data key. |
| age | The public-key format used to wrap the data key. |

## File

The vault is TOML. `version` is `2`. shh still reads version `1`. Unknown versions fail.

`recipients` maps a name to an age public key. Names and public keys are plaintext.

`wrapped_keys` holds one wrapped copy of the data key per recipient.

`secrets` maps a name to AES-256-GCM ciphertext. The name binds the value. A swapped value fails open. Names are plaintext.

shh draws the data key and each nonce from `crypto/rand`.

## MAC

shh opens the data key, checks the MAC, then opens secret values. `hmac.Equal` compares the MAC.

A partial edit fails that check. The attacker does not have the data key, so the attacker cannot write a valid MAC for that edit.

A full replacement is different. The public recipients are in the file. A person who can replace the file can mint a new data key, wrap it to those recipients, and write a new MAC. Decrypt succeeds. `shh set`, `shh edit`, and `shh rm` then keep that recipient set.

A current recipient can also edit the vault and recompute the MAC. That person already has the data key.

`shh doctor` does not check the MAC.

## People

`shh users add` wraps the same data key for the new recipient. Old values stay readable by the new recipient.

`shh users remove` mints a new data key and encrypts the values again. The removed key cannot open the new file. The values do not change. Change them at the provider when an extractable key leaks or leaves. Old git blobs stay readable by a key that was a recipient at that time.

shh refuses to remove the last recipient.

## Plugins

A recipient string can name an age plugin. shh allows `yubikey` and `se` by default. `SHH_ALLOWED_AGE_PLUGINS` adds names for the current process. A secret in the vault cannot set that name.

Parse does not start a program. Wrap and decrypt start `age-plugin-<name>` from `PATH`. Put those programs in a directory that you trust.

## GitHub

`shh users add NAME` requests `https://github.com/NAME.keys` over HTTPS. Redirects must stay on `github.com`. The limit is 3 redirects, 30 seconds, and 1 MiB. shh uses the first `ssh-ed25519` line. It does not ask you to compare a fingerprint.

`shh init` and `shh login` can derive an age key from an ed25519 file in `~/.ssh`. They use the first file that they find. Directory order is the rule.

## Child environment

`shh run` and `shh shell` inject vault names into the child. shh drops `SHH_AGE_KEY`, `SHH_PLAINTEXT`, and `SHH_ALLOWED_AGE_PLUGINS` from that child.

shh also skips a fixed list of dangerous names, on write and on inject. The list includes `PATH`, `LD_PRELOAD`, `BASH_ENV`, `NODE_OPTIONS`, and `JAVA_TOOL_OPTIONS`. It does not include every name that can start a program. `LD_AUDIT`, `GIT_SSH_COMMAND`, and `TAR_OPTIONS` are examples that are still absent.

`shh env` quotes values with POSIX single quotes. You must pass `--stdout`.

## Passphrase

argon2id uses 256 MiB, time 3, and 4 threads. The salt is the public label `shh-brainkey-v1`. Do not change those parameters. The same phrase yields the same key in every project.

The vault is public. A weak phrase allows an offline guess. Use 8 generated diceware words. Enrollment rejects a phrase shorter than 12 characters. That floor does not measure entropy.

See `docs/passphrase-security.md`.

## Recovery QR

The QR payload is an extractable age secret. shh rejects URLs and other non-keys. shh limits image size. `--qr-out` writes mode `0600`.

Treat the PNG, the terminal QR, and the printed page as the private key. Remove the PNG after import. Do not commit it.

## Edit file

`shh edit` writes plaintext to `.shh-edit-*.env` beside the vault. The mode is `0600`. Do not commit that file. A normal exit removes it. `SIGKILL` can leave it.

## Writes

shh writes a temp file in the same directory, sets mode `0600`, and renames it over the vault. Two writers do not lock the file. The last writer wins.

## Plaintext bypass

`SHH_PLAINTEXT` names a plaintext file. shh skips decrypt and prints a warning on stderr. A parent environment can set this. The vault cannot set it for a child.

## Trust

shh trusts these parties:

- GitHub, for the SSH keys behind `shh users add`.
- The OS keyring, for the private key.
- The git host, for who may change `.env.enc`.
- The local machine. A person who can read your user memory can read open secrets.

## What shh does not do

| Limit | Result |
| --- | --- |
| Full file replacement | Decrypt can succeed for the public recipients. |
| Recipient with the data key | That person can recompute the MAC. |
| Secret already seen | Removal does not change the upstream value. |
| Git history | An old recipient can open the old blob. |
| Secret names | Names stay plaintext. |
| `shh set KEY value` | Other users on the machine can see the argument. Use `shh set KEY -`. |
| `shh doctor` | A broken MAC can still look healthy. |
| Conflict merge | Recipients can appear or disappear. Read the list before you commit. |
| Memory | Go does not wipe the data key or the plaintext. |
