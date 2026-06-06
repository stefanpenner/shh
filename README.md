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
shh get KEY                           # print a single secret value
shh rm KEY                            # remove a secret
shh edit                              # edit all secrets in $EDITOR
shh list                              # list secret names
shh env --stdout                      # print export statements (requires --stdout)
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

## CI / Production

Create a deploy key for environments that don't have a GitHub identity:

```bash
shh users add --name production-deploy
# Prints a secret key — store it as SHH_AGE_KEY in your CI/deploy platform
git add .env.enc && git push
```

Then in your CI pipeline or Dockerfile:

```bash
shh run -- node app.js            # secrets injected, SHH_AGE_KEY auto-filtered
# or
eval $(shh env --stdout)          # export secrets into the current shell
```

You manage **one** platform secret (`SHH_AGE_KEY`); everything else lives in `.env.enc`.

If you already have an age public key, pass it directly:

```bash
shh users add --name staging --key age1xyzt...
```

## Hardware keys (YubiKey & Secure Enclave)

`shh` supports [age plugin](https://github.com/FiloSottile/awesome-age#plugins)
recipients, so a key can be backed by hardware whose private key **can never be
extracted** — a YubiKey or Apple's Secure Enclave — instead of a copyable secret
string.

```bash
# YubiKey (private key lives on the device; decrypt needs a touch)
brew install age-plugin-yubikey
age-plugin-yubikey --generate                       # prints age1yubikey1… + an identity file
shh users add --name stef-yubikey --key age1yubikey1…
shh login --identity ~/age-yubikey-identity.txt     # store the identity stub in your keyring

# Apple Secure Enclave (built into the Mac; decrypt needs Touch ID)
brew install age-plugin-se
age-plugin-se keygen -o se-key.txt                  # recipient is in the file header
shh users add --name stef-laptop --key "$(age-plugin-se recipients -i se-key.txt)"
shh login --identity se-key.txt
```

Adding or re-wrapping for a plugin recipient needs the **plugin binary**
installed (encryption is public-key only — no hardware required). **Decrypting**
needs the **hardware itself** present (touch / PIN / biometric).

## Passphrase ("brain") key

A key derived from a passphrase — nothing to store, nothing to lose. The only
recovery path that survives losing every device.

```bash
shh users add --name failsafe --passphrase   # prompts; adds a derived recipient
shh login --passphrase                         # re-derive to unlock
```

- It's a normal age key (argon2id → X25519), so it shows as `[extractable]`.
- `.env.enc` is committed, so it can be brute-forced offline → **use a generated
  8-word passphrase**, and keep it complementary to a hardware key, not your only
  failsafe.
- Details + threat model: [`docs/passphrase-security.md`](docs/passphrase-security.md).

### Extractable key, or non-extractable?

| | **Extractable** (X25519 — the default) | **Non-extractable** (YubiKey / Secure Enclave) |
|---|---|---|
| The private key is… | a copyable string | sealed in hardware, never leaves it |
| Back up / sync / recover | ✅ yes | ❌ no — can't be copied |
| Use as a CI `SHH_AGE_KEY` | ✅ yes | ❌ no (needs the device) |
| If the store/laptop is compromised | the key leaks | the key is safe |
| Lost device | recover from your backup | **locked out** unless you enrolled a second key |

- **CI / deploy keys → extractable.** No human, no hardware; the key must live as
  a platform secret.
- **Your everyday key → non-extractable.** Secure Enclave: free, and a stolen
  laptop or leaked backup never exposes it.
- **An offline root → a YubiKey in a safe.** Enroll **two** (each its own
  recipient) — there's no recovery for hardware keys.
- **Sync a key only if it's extractable**, and only in an end-to-end-encrypted
  store. Syncing means accepting it's copyable — right for a *recovery* key, wrong
  for one whose job is to be un-copyable.

> **Retiring or losing an extractable key requires rotating your secrets.**
> `shh users remove` re-wraps the data key for the *remaining* recipients, but the
> removed key already saw every secret value and can still decrypt the **old**
> `.env.enc` in git history. So whenever an extractable key is exposed or rotated
> out, treat its secrets as compromised and **change the values** (`shh users
> remove …`, then re-generate + `shh set` each affected secret). Hardware keys
> never leak a copyable secret, so retiring one is just `shh users remove`.

The recipient's **key encodes its type** (`age1…` extractable, `age1yubikey1…` /
`age1se1…` hardware), and `shh users list` tags each one (`[extractable]`,
`[yubikey]`, `[secure-enclave]`) so you can see which keys are in scope for the
rotation rule above.

## How It Works

`shh` uses **envelope encryption**: a random 32-byte AES-256 **data key** encrypts all secrets, and that data key is wrapped (age-encrypted) individually to each recipient.

- **Adding a user** — re-wraps the existing data key for the new recipient. Secrets don't change.
- **Removing a user** — generates a new data key, re-encrypts all secrets, wraps only for remaining recipients. The removed key can't read *new* versions — but it already saw the current values and can still decrypt the old `.env.enc` in git history, so if it was an extractable key, rotate the secret values too.

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

## Claude Code Integration

If your team uses [Claude Code](https://claude.com/claude-code), copy [`CLAUDE.md.example`](CLAUDE.md.example) into your project's `CLAUDE.md` (or append it to an existing one). This teaches Claude how to manage secrets with `shh` — it will use the right commands, avoid leaking values, and follow best practices automatically.

```bash
# In your project directory:
curl -sL https://raw.githubusercontent.com/stefanpenner/shh/main/CLAUDE.md.example >> CLAUDE.md
```

## License

[MIT](LICENSE)
