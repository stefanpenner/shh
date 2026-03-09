# shh

Commit your secrets. Yes, really.

* Encrypted secrets live in your repo, safe to push, easy to share.
* Add teammates by GitHub username — `shh users add alice` fetches their SSH key automatically.
* No GitHub? Pass an [age](https://github.com/FiloSottile/age) key directly.
* One binary, no dependencies. Private keys stay in your OS keyring.

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

No plaintext `.env` file ever touches disk.

## Commands

```bash
shh set KEY value                     # add or update a secret
shh rm KEY                            # remove a secret
shh edit                              # edit all secrets in $EDITOR
shh list                              # list secret names
shh env                               # print export statements
shh shell                             # open a shell with secrets loaded
shh whoami                            # show your key, name, and GitHub identity
```

All commands default to `.env.enc`. Pass a different file as the last argument:

```bash
shh set KEY value staging.env.enc
shh shell staging.env.enc
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
shh init                              # create a new identity
shh login                             # restore existing identity (auto-detects SSH/GitHub)
shh logout                            # remove key from OS keyring
shh whoami                            # show your key and identity
```

## How It Works

- **One file** — `.env.enc` is a TOML file containing encrypted secrets, recipients, and the wrapped data key
- **Private keys** stay in your OS keyring (macOS Keychain, GNOME/KDE Secret Service, Windows Credential Manager). Set `SHH_AGE_KEY` to override for CI/Docker
- **GitHub integration** — `shh users add alice` fetches their public SSH key from GitHub and converts it to an age key. `shh login` auto-detects your identity via the `gh` CLI
- **Encryption** uses [age](https://age-encryption.org) for key wrapping and AES-256-GCM for per-value encryption
- **Integrity** is verified with HMAC-SHA256 on every decrypt
- **`shh shell`** decrypts secrets into memory only — they exist as env vars in the subshell and are gone when you exit

## License

[MIT](LICENSE)
