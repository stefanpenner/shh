# shh

> **Warning:** This project is experimental and should not be used beyond testing at this time.

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

All commands default to `.env.enc`. Pass a different file as the last argument:

```bash
shh set KEY value staging.env.enc
shh shell staging.env.enc
```

Or use `-e` to select an environment by name:

```bash
shh list -e production                # reads production.env.enc
shh shell -e staging                  # opens shell with staging.env.enc
shh run -e production -- node app.js  # runs with production secrets
```

Already have a `.env` file? Encrypt it:

```bash
shh encrypt .env                      # creates .env.enc (then delete .env)
```

### Running commands

`shh run` injects secrets into a single command without starting a subshell:

```bash
shh run -- node server.js
shh run -- docker compose up
shh run staging.env.enc -- ./deploy.sh
```

`SHH_AGE_KEY` is automatically filtered out of the child process environment.

### Templating

`shh template` substitutes `{{SECRET_NAME}}` placeholders with decrypted values and writes to stdout — no plaintext file ever hits disk:

```bash
shh template config.yml.tpl | kubectl apply -f -
shh template config.yml.tpl > config.yml
cat config.yml.tpl | shh template -          # read from stdin
shh template config.yml.tpl production.env.enc  # use a specific env file
```

Template file (`config.yml.tpl`):
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-app
data:
  api-key: {{API_KEY}}
  db-password: {{DB_PASSWORD}}
```

Unresolved placeholders (referencing secrets that don't exist) cause an error listing the missing keys.

### Diagnostics

```bash
shh doctor
```

Checks your age key, GitHub CLI auth, SSH keys, encrypted file, and whether your key is in the recipients list. Useful for onboarding and debugging access issues.

## Team Workflow

```bash
# You (project owner)
shh init
shh set SECRET supersecret
git add .env.enc
git push

# Add a teammate
shh users add alice
git add .env.enc
git push

# Alice (joining the project)
shh login                             # auto-detects SSH key via GitHub
shh shell                             # works immediately
```

### Managing users

```bash
shh users list                        # show who has access
shh users add <username-or-key>       # add by GitHub username or age key
shh users remove <user|#>            # revoke access
```

### Identity

```bash
shh init                              # create identity (uses gh + SSH key)
shh login                             # restore existing identity (auto-detects SSH/GitHub)
shh logout                            # remove key from OS keyring
shh whoami                            # show your key and identity
```

## Git Merge Support

`.env.enc` files are designed to be merge-friendly:

- **Per-recipient wrapped keys** — each recipient's data key is wrapped individually, so adding different teammates on different branches won't conflict
- **Auto-resolve** — if a merge conflict occurs, any `shh` command automatically detects it, decrypts all three versions (ancestor/ours/theirs), performs a semantic 3-way merge, and stages the resolved file
- **True conflicts** (same secret modified differently on both branches) are reported clearly so you can fix them manually

For proactive conflict prevention, configure the built-in merge driver:

```bash
# .gitattributes (commit this)
*.env.enc merge=shh

# ~/.gitconfig (each developer)
[merge "shh"]
    name = shh encrypted env merge
    driver = shh merge %O %A %B
```

Even without the merge driver, conflicts are resolved automatically on the next `shh` command.

## File Format

`.env.enc` is a TOML file:

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

- **`recipients`** — maps GitHub identities to age public keys
- **`wrapped_keys`** — the same AES-256 data key, individually wrapped (age-encrypted) to each recipient. One entry per recipient means adding teammates on separate branches won't conflict
- **`secrets`** — each value encrypted with AES-256-GCM using the data key, with the key name as authenticated data
- **`mac`** — HMAC-SHA256 over all fields, verified on every decrypt

## How It Works

- **One file** — `.env.enc` is committed to your repo alongside your code
- **Private keys** stay in your OS keyring (macOS Keychain, GNOME/KDE Secret Service, Windows Credential Manager). Set `SHH_AGE_KEY` to override for CI/Docker. Set `SHH_PLAINTEXT` to point at a plain `.env` file to skip decryption entirely (useful for CI/testing)
- **GitHub integration** — `shh users add alice` fetches their public SSH key from GitHub and converts it to an age key. `shh login` auto-detects your identity via the `gh` CLI
- **Encryption** uses [age](https://age-encryption.org) for key wrapping and AES-256-GCM for per-value encryption. Each recipient gets their own wrapped copy of the data key
- **Integrity** is verified with HMAC-SHA256 on every decrypt
- **`shh shell`**, **`shh run`**, and **`shh template`** decrypt secrets into memory only — they exist as env vars in the subprocess (or stdout output) and are gone when it exits
- **`shh env`** warns when stdout is piped to a non-TTY (suppress with `-q`)

## License

[MIT](LICENSE)
