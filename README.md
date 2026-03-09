# shh

Encrypted secrets for your team. One binary, no dependencies.

Your secrets live in `.env.enc` — a single TOML file that's encrypted, safe to commit, and shareable with teammates. Private keys stay in your OS keyring (macOS Keychain, GNOME/KDE Secret Service, or Windows Credential Manager).

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
shh init                              # one-time setup (stores key in OS keyring)
shh set DATABASE_URL postgres://localhost/mydb
shh set API_KEY sk-secret123
shh shell                             # launch a shell with secrets loaded
```

That's it. No plaintext `.env` file ever touches disk.

## Day-to-Day Usage

```bash
shh set KEY value                     # add or update a secret
shh rm KEY                            # remove a secret
shh edit                              # edit all secrets in $EDITOR
shh shell                             # open a shell with secrets as env vars
shh decrypt                           # print secrets to stdout
```

All commands default to `.env.enc`. To use a different file, pass it as the last argument:

```bash
shh set KEY value staging.env.enc
shh shell staging.env.enc
```

Already have a `.env` file? Encrypt it:

```bash
shh encrypt .env                      # creates .env.enc, then delete .env
```

## Team Workflow

```bash
# You (project owner)
shh init
shh set SECRET supersecret
git add .env.enc
git push

# Add a teammate (uses their GitHub SSH key)
shh keys add-github alice
git add .env.enc
git push

# Alice (joining the project)
shh init --from-ssh
shh shell                             # works immediately
```

### Managing access

```bash
shh keys list                         # show who has access
shh keys add <age-pubkey> [name]      # add by public key
shh keys add-github <username>        # add by GitHub username
shh keys remove <key|#>              # revoke access
```

Adding or removing a key re-wraps the encryption key in `.env.enc`.

## What Gets Committed

| File | Contents | Commit? |
|------|----------|---------|
| `.env.enc` | Encrypted secrets, recipients, data key | Yes |
| `.env` | Plaintext secrets | **Never** |

Everything lives in a single `.env.enc` TOML file:

```toml
version = 1
mac = "a1b2c3..."
data_key = "age-encrypted-data-key..."

[recipients]
alice = "age1abc..."
stefan = "age1def..."

[secrets]
API_KEY = "AES-256-GCM-encrypted..."
DATABASE_URL = "AES-256-GCM-encrypted..."
```

Keys are visible in diffs. Values are encrypted.

## How It Works

- **Private keys** are stored in your OS keyring — never on disk. Set `SHH_AGE_KEY` to override (for CI/Docker/headless)
- **Encryption** uses [age](https://age-encryption.org) for key wrapping and AES-256-GCM for per-value encryption
- **Integrity** is verified with HMAC-SHA256 on every decrypt
- **`shh shell`** decrypts secrets into memory only — they exist as env vars in the subshell and are gone when you exit
- **`--from-ssh`** converts your existing ed25519 SSH key to an age key, so teammates just need their GitHub username

## Command Reference

```
shh init [--from-ssh [path]]          Set up your key (OS keyring)
shh set <KEY> <VALUE> [file]          Add/update a secret
shh rm <KEY> [file]                   Remove a secret
shh edit [file]                       Edit secrets in $EDITOR
shh shell [file]                      Shell with secrets loaded
shh encrypt <file>                    Encrypt a .env file
shh decrypt [file]                    Print decrypted secrets
shh keys list                         List authorized keys
shh keys add <key> [name]             Add recipient
shh keys add-github <user>            Add recipient via GitHub
shh keys remove <key|#>              Remove recipient
```

All commands default to `.env.enc` when `[file]` is omitted.

## License

[MIT](LICENSE)
