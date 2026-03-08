# shh

Encrypted `.env` files with [age](https://age-encryption.org) + [sops](https://github.com/getsops/sops), keys in macOS Keychain.

```
brew install stefanpenner/tap/shh
```

## Quick start

```bash
shh init                        # age key → Keychain (Touch ID)
shh encrypt .env                # .env → .env.enc
shh shell .env.enc              # subshell with secrets loaded
```

## Commands

```
shh init [--from-ssh]           Set up age key
shh encrypt <file>              Encrypt .env → .env.enc
shh decrypt <file>              Print decrypted secrets
shh edit <file>                 Edit in $EDITOR
shh shell <file>                Subshell with secrets as env vars
shh set <file> KEY value        Add or update a secret
shh rm <file> KEY               Remove a secret
shh keys list                   Show authorized keys
shh keys add <key> [name]       Add a recipient
shh keys add-github <user>      Add by GitHub username
shh keys remove <key|#>         Remove a recipient
```

## Team workflow

```bash
# You (project owner)
shh init
shh encrypt .env
shh keys add-github alice       # adds Alice by GitHub SSH key
git add .env.enc .sops.yaml .age-keys
git commit -m "add encrypted secrets"

# Alice
shh init --from-ssh             # derives age key from ~/.ssh/id_ed25519
shh shell .env.enc              # she's in
```

## How it works

- Private key lives in **macOS Keychain**, unlocked via Touch ID
- `.env.enc` is encrypted with sops using age — safe to commit
- `.sops.yaml` lists public keys (recipients) — not secret
- `shh shell` decrypts into env vars in a subshell — secrets never touch disk
- `--from-ssh` converts ed25519 SSH keys to age keys, so teammates don't need to exchange keys manually

## What to commit

```
.env.enc      ✓  encrypted secrets
.sops.yaml    ✓  recipient public keys
.age-keys     ✓  key → name mapping
.env          ✗  add to .gitignore
```

## Requirements

```bash
brew install age sops
```

Optional (for `--from-ssh` and `keys add-github`):

```bash
go install github.com/Mic92/ssh-to-age/cmd/ssh-to-age@latest
```
