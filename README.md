# shh

> **Warning:** Experimental — not yet ready for production use.

🤫 Commit your secrets. Yes, really.

* Encrypted secrets live in your repo, safe to push, easy to share.
* Add teammates by GitHub username — `shh users add alice` fetches their SSH key automatically.
* No GitHub? Pass an [age](https://github.com/FiloSottile/age) key directly.
* One binary, one dependency ([`gh`](https://cli.github.com)). Private keys stay in your OS keyring.

## Install

```bash
brew install stefanpenner/tap/shh
```

Or from source:

```bash
go install github.com/stefanpenner/shh@latest
```

## Quick Start

```bash
shh init                              # one-time setup (requires gh auth login)
shh set DATABASE_URL postgres://localhost/mydb
shh set API_KEY sk-secret123
shh shell                             # launch a shell with secrets loaded
```

No plaintext `.env` file ever touches disk.

## Commands

```bash
shh set KEY value                     # add or update a secret
shh rm KEY                            # remove a secret
shh edit                              # edit all secrets in $EDITOR
shh list                              # list secret names
shh env                               # print export statements
shh shell                             # open a shell with secrets loaded
shh run -- <cmd> [args...]            # run a command with secrets injected
shh template <file>                   # render a template with secrets substituted
shh doctor                            # check your setup for common issues
shh whoami                            # show your key and identity
```

All commands default to `.env.enc`. Use `-e` to pick an environment:

```bash
shh shell -e staging                  # opens shell with staging.env.enc
shh run -e production -- node app.js  # runs with production secrets
```

Or pass a filename directly:

```bash
shh set KEY value staging.env.enc
```

Already have a `.env` file? Encrypt it:

```bash
shh encrypt .env                      # creates .env.enc (then delete .env)
```

## Team Workflow

```bash
# You (project owner)
shh init
shh set SECRET supersecret
git add .env.enc && git push

# Add a teammate
shh users add alice
git add .env.enc && git push

# Alice (joining the project)
shh login                             # auto-detects SSH key via GitHub
shh shell                             # works immediately
```

```bash
shh users list                        # show who has access
shh users add <username-or-key>       # add by GitHub username or age key
shh users remove <user|#>            # revoke access (rotates data key)
```

## How It Works

`shh` uses **envelope encryption**: a random 32-byte AES-256 **data key** encrypts all secrets, and that data key is wrapped (age-encrypted) individually to each recipient.

- **Adding a user** — re-wraps the existing data key for the new recipient. Secrets don't change.
- **Removing a user** — generates a new data key, re-encrypts all secrets, wraps only for remaining recipients. The old key becomes useless.

Private keys stay in your OS keyring (macOS Keychain, GNOME/KDE Secret Service, Windows Credential Manager). Set `SHH_AGE_KEY` to override for CI/Docker. Set `SHH_PLAINTEXT` to point at a plain `.env` file to skip decryption entirely.

### File Format

`.env.enc` is TOML:

```toml
version = 2
mac = "hmac-sha256-hex"

[recipients]
"https://github.com/alice" = "age1..."
"https://github.com/bob" = "age1..."

[wrapped_keys]
"https://github.com/alice" = "base64-data-key-wrapped-to-alice"
"https://github.com/bob" = "base64-data-key-wrapped-to-bob"

[secrets]
DATABASE_URL = "base64-aes-256-gcm-ciphertext"
API_KEY = "base64-aes-256-gcm-ciphertext"
```

| Section | Purpose |
|---------|---------|
| `recipients` | Maps identities to age public keys |
| `wrapped_keys` | The data key, individually wrapped to each recipient — one entry per recipient so branch additions don't conflict |
| `secrets` | Values encrypted with AES-256-GCM using the data key; key name is authenticated data |
| `mac` | HMAC-SHA256 over all fields, verified on every decrypt |

## Git Merge Support

Per-recipient wrapped keys mean adding teammates on different branches won't conflict. If a merge conflict does occur, any `shh` command auto-detects it, performs a semantic 3-way merge, and stages the result. True conflicts (same key modified both sides) are reported for manual resolution.

For proactive conflict prevention:

```bash
# .gitattributes (commit this)
*.env.enc merge=shh

# ~/.gitconfig (each developer)
[merge "shh"]
    name = shh encrypted env merge
    driver = shh merge %O %A %B
```

## License

[MIT](LICENSE)
