# shh

**Experimental.** Do not use in production.

Encrypts secret values into `.env.enc`. Commit that file. Private key stays in the OS keyring.

age wraps the data key. AES-256-GCM encrypts values.

## When to use

Small team, one repo, age keys. Secrets server is too much.

Use a secrets server when:
- Values must expire
- Many apps share the same values
- You must record each read
- Reader is a cluster workload with a cloud role and no age key

## What to store

Only values you can rotate at the provider.

1. Create the new value.
2. `shh set KEY -`
3. Disable the old value.

Do not store seed phrases, recovery codes, or the age key itself. Git keeps every past `.env.enc`. Old recipients can still open old files.

## Install

```bash
brew install stefanpenner/tap/shh
```

or

```bash
go install github.com/stefanpenner/shh@latest
```

`shh init` and `shh users add` need `gh`.

## Start

```bash
gh auth login
shh init
shh set DATABASE_URL -
shh shell
```

`shh init` derives an age key from the first ed25519 key in `~/.ssh`, or generates one.

## Commands

| Command | Action |
| --- | --- |
| `set KEY -` | Add or change one value (stdin) |
| `get KEY` | Print one value |
| `rm KEY` | Remove one name |
| `edit` | Edit all values in `$EDITOR` |
| `list` | Show names |
| `env --stdout` | Print `export` lines |
| `shell` | Shell with values |
| `run -- CMD` | Run command with values |
| `template FILE` | Replace `{{NAME}}` |
| `paper encode` | Gzip vault to QR PNGs |
| `paper decode` | Restore vault from QR PNGs |
| `encrypt FILE` | Encrypt plaintext env to `FILE.enc` |
| `doctor` | Check local setup |
| `whoami` | Show public key |
| `login` | Store key in OS keyring |
| `logout` | Remove key from OS keyring |
| `users` | Show recipients |
| `users add` | Add recipient |
| `users remove` | Remove recipient and rotate data key |

Default file: `.env.enc`. `-e NAME` selects `NAME.env.enc`.

## Team

```bash
shh users add alice
git add .env.enc && git commit -m "add alice" && git push
```

Alice runs `shh login` then `shh shell`.

`shh users add NAME` reads the first `ssh-ed25519` key from `https://github.com/NAME.keys`.

## Keys

| Kind | CI | Lost device |
| --- | --- | --- |
| Extractable X25519 | Yes (`SHH_AGE_KEY`) | Use your copy |
| YubiKey / Secure Enclave | No | Need a second recipient |

Use extractable for CI. Use hardware for daily work. Enroll two hardware keys if hardware is the recovery path.

If an extractable key leaks, rotate the values at the provider.

## Recovery QR

```bash
shh users add --name recovery --qr --qr-out ~/Desktop/shh-recovery.png
```

Store the printed `AGE-SECRET-KEY-1…` in a password manager. Delete the PNG. Do not commit it.

On a new machine:

```bash
shh login --qr-file ~/path/to/shh-recovery.png
```

Or set `SHH_AGE_KEY`.

## CI

```bash
shh users add --name production-deploy
```

Store the secret as `SHH_AGE_KEY`. Do not print it.

```bash
shh run -- node app.js
```

## Hardware

```bash
brew install age-plugin-yubikey
age-plugin-yubikey --generate
shh users add --name yubikey --key age1yubikey1…
shh login --identity ~/age-yubikey-identity.txt
```

Same pattern for `age-plugin-se` and TPM tag keys (`age1tag1…`).

## Passphrase

```bash
shh users add --name failsafe --passphrase
shh login --passphrase
```

Use 8 diceware words. Minimum 12 characters. See `docs/passphrase-security.md`.

## File

`.env.enc` is TOML (v2).

| Field | Content |
| --- | --- |
| `recipients` | Name → age public key (plaintext) |
| `wrapped_keys` | Data key wrapped per recipient |
| `secrets` | AES-256-GCM values (name-bound) |
| `mac` | HMAC-SHA256 over the fields |

Partial edits fail the MAC. Full replacement is possible by someone who can write the file. `shh set`/`edit`/`rm`/`encrypt` stop if recipients differ from `HEAD` unless `--accept-recipients`.

## Paper

```bash
shh paper encode --out shh-paper
shh paper decode shh-paper --out restored.env.enc
```

QR sheet is a copy of `.env.enc`. Still needs a private key. Delete the PNGs after printing.

## Merge

`shh merge` is a git merge driver.

```bash
# .gitattributes
*.env.enc merge=shh
```

```gitconfig
[merge "shh"]
    name = shh encrypted env merge
    driver = shh merge %O %A %B
```

Stops on differing recipient sets or conflicting values for one name. Resolve recipients with `shh users`, then merge again.

## More

- `SECURITY.md`
- `docs/passphrase-security.md`
- `docs/security-audit-v0.7.0.md`

## License

MIT.
