# shh

**Warning:** shh is experimental. Do not use it in production yet.

shh encrypts secret values into `.env.enc`. You can commit that file. The private key stays in the OS keyring.

age is the public-key format. A recipient is an age public key. The data key is the 32-byte AES key for the values.

## When to use

Use shh when a secrets server is too much. A small team shares one repository. People open the vault with age keys. A CI job can use one age key.

[What to store](#what-to-store) names the values for the vault.

Use a secrets server in these cases.

- The value must expire.
- Many applications share the same values.
- You must record each read.
- The reader is a cluster workload. It has a cloud role. It has no age key.

A secrets server has one of these forms.

- You run HashiCorp Vault or OpenBao.
- Doppler, Infisical, Bitwarden Secrets Manager, and 1Password secrets automation host a secrets server.
- AWS Secrets Manager, Google Secret Manager, and Azure Key Vault serve one cloud each.

## What to store

Store a value only when you can change it at the provider.

1. Create the new value at the provider before you disable the old value.
2. Write the new value with `shh set`.
3. Disable the old value at the provider.

You can store an API token, a database password, or a cloud access key when the provider accepts two values that both work.

`shh users remove` rotates the data key. It does not change the value. Git keeps every past `.env.enc`. A key that was a recipient at that time can still open that file.

Change those values at the provider. A value you cannot change still works.

Do not store a value in these cases.

- The value is a seed phrase or a wallet private key. The old key can still sign.
- The value is an account recovery code. A person who opens the vault can use that code on the account that can change the other values.
- You already published the private key in a contract or in an app you cannot update.
- The key encrypts data you cannot encrypt again. The old key can still decrypt that data.
- The value is the age key, the recovery key, or the passphrase for this vault. The same passphrase makes the same key in every project.

## Install

```bash
brew install stefanpenner/tap/shh
```

From source:

```bash
go install github.com/stefanpenner/shh@latest
```

`shh init` and `shh users add NAME` need the GitHub CLI (`gh`).

## Start

1. Run `gh auth login`.
2. Run `shh init`.
3. Run `shh set DATABASE_URL -`.
4. Run `shh shell`.

`shh set KEY -` reads the value from stdin. The value does not enter shell history.

`shh init` derives the age key from the first ed25519 file in `~/.ssh`. Directory order decides which file is first. With no ed25519 file, `shh init` generates a new age key.

## Commands

| Command | Action |
| --- | --- |
| `set KEY -` | Add or change one value. `-` reads stdin. |
| `get KEY` | Print one value. |
| `rm KEY` | Remove one name. |
| `edit` | Edit all values in `$EDITOR`. |
| `list` | Show names. |
| `env --stdout` | Print `export` lines. You must pass `--stdout`. |
| `shell` | Start a shell with the values. |
| `run -- CMD` | Start a command with the values. |
| `template FILE` | Replace `{{NAME}}` and print the file. |
| `paper encode` | Gzip the vault and write QR PNG files. |
| `paper decode` | Restore the vault from those QR PNG files. |
| `encrypt FILE` | Encrypt a plaintext env file to `FILE.enc`. |
| `doctor` | Check the local setup. |
| `whoami` | Show your public key. |
| `login` | Store a key in the OS keyring. |
| `logout` | Remove your key from the OS keyring. |
| `users` | Show recipients. |
| `users add` | Add a recipient. |
| `users remove` | Remove a recipient and rotate the data key. |

The default file is `.env.enc`. `-e NAME` selects `NAME.env.enc`. You can pass a file path as the last argument.

```bash
shh run -e production -- node app.js
```

`shh template` inserts the raw value. Quote the value for the target format.

After `shh encrypt .env`, remove the plaintext file.

## Team

```bash
shh users add alice
git add .env.enc
git commit -m "shh: add alice"
git push
```

Alice runs `shh login`, then `shh shell`.

`shh users add NAME` reads `https://github.com/NAME.keys`. It uses the first `ssh-ed25519` line. `shh users add --key age1…` uses an age public key that you supply.

## Keys

| Kind | Private key | CI | Lost device |
| --- | --- | --- | --- |
| Extractable X25519 | A string you can copy | Yes. Store it as `SHH_AGE_KEY`. | Use your copy. |
| YubiKey or Secure Enclave | Stays on the device | No | A second recipient must already exist. |

Use an extractable key for CI. Use a hardware key for daily work. Enroll two hardware keys when hardware is the recovery path. A hardware key has no copy.

If an extractable key leaks, change the values at the provider. See [What to store](#what-to-store).

`shh users list` marks each recipient. `[extractable]` means that leak rule applies.

## Recovery QR

Keep two recipients. One is the daily key. One is the recovery key.

```bash
shh users add --name recovery --qr --qr-out ~/Desktop/shh-recovery.png
```

shh prints `AGE-SECRET-KEY-1…` once. Store that string in a password manager. The PNG and the terminal QR hold the same secret. Import or print the PNG. Then remove the PNG. Do not commit the PNG.

On a new machine:

```bash
shh login --qr-file ~/path/to/shh-recovery.png
shh doctor
shh env --stdout
```

Or set `SHH_AGE_KEY` to the secret string.

The lifecycle model is `specs/RecoveryQR.tla`.

## CI

```bash
shh users add --name production-deploy
```

Store the printed secret as `SHH_AGE_KEY` in CI. Do not print it in logs.

```bash
shh run -- node app.js
```

shh removes `SHH_AGE_KEY` from the child environment.

## Hardware

Decrypt needs the device.

```bash
brew install age-plugin-yubikey
age-plugin-yubikey --generate
shh users add --name stef-yubikey --key age1yubikey1…
shh login --identity ~/age-yubikey-identity.txt
```

```bash
brew install age-plugin-se
age-plugin-se keygen -o se-key.txt
shh users add --name stef-laptop --key "$(age-plugin-se recipients -i se-key.txt)"
shh login --identity se-key.txt
```

On wrap or decrypt, shh runs `age-plugin-yubikey` or `age-plugin-se` from `PATH`. The default allowlist is `yubikey` and `se`. `SHH_ALLOWED_AGE_PLUGINS` adds names for that process.

## Passphrase

```bash
shh users add --name failsafe --passphrase
shh login --passphrase
```

Use 8 generated diceware words. Enrollment rejects a phrase shorter than 12 characters. The key is extractable. See `docs/passphrase-security.md`.

## File

`.env.enc` is TOML.

| Field | Content |
| --- | --- |
| `version` | `2`. shh can still read version `1`. |
| `recipients` | Name to age public key. Names are plaintext. |
| `wrapped_keys` | Data key, wrapped once per recipient. |
| `secrets` | AES-256-GCM values. The name binds each value. |
| `mac` | HMAC-SHA256 over those fields. The MAC key is the data key. |

A partial edit fails the MAC check. A person who can replace the file can write a new valid file for the public recipients. `shh set`, `shh edit`, `shh rm`, and `shh encrypt` stop when that recipient set differs from `HEAD`. Pass `--accept-recipients` after you review `shh users list`. `shh doctor` does not check the MAC.

`SHH_PLAINTEXT` selects a plaintext file and skips decrypt. shh prints a warning on stderr.

More limits are in `SECURITY.md`.

## Paper

`shh paper encode` gzips the vault and writes QR PNG files. One code holds 1,400 bytes of that gzip stream at high error correction. A smaller vault uses a smaller code. A larger vault uses the next code, up to 16. A 4,296-character code is larger, and this scanner does not read it reliably. The PNG files are mode `0600`.

```bash
shh paper encode --out shh-paper
shh paper decode shh-paper --out restored.env.enc
```

Print the sheet. Scan every code. Decode writes a new file. It does not replace a file that already exists.

The sheet is a copy of `.env.enc`. It does not show secret values. A person who scans it still needs a private key. Remove the PNG files after you print them. Do not commit them.

`shh paper encode` refuses a plaintext env file.

## Merge

Each write rewrites `.env.enc`. Git can report a conflict.

`shh merge` is a git merge driver. These commands also merge a conflicted file and stage it:

- `set`
- `edit`
- `rm`
- `encrypt`
- `users`
- `login`
- `whoami`

The merge stops when the recipient sets differ. It does not add or remove a recipient. Two values for one name also stop the merge.

Add or remove a person with `shh users`. Then merge again.

```bash
# .gitattributes
*.env.enc merge=shh
```

```gitconfig
[merge "shh"]
    name = shh encrypted env merge
    driver = shh merge %O %A %B
```

Put the driver block in `~/.gitconfig` on each machine.

`shh get`, `shh run`, `shh shell`, `shh env`, `shh doctor`, and `shh template` do not merge a conflict.

## Agents

Copy `CLAUDE.md.example` into the project `CLAUDE.md`.

## More

- `SECURITY.md`
- `docs/passphrase-security.md`
- `docs/security-audit-v0.7.0.md`

## License

MIT. See `LICENSE`.
