# shh

Encrypted secrets manager for teams. Age encryption, envelope encryption, per-recipient key wrapping.

## Tech stack

- Go, cobra CLI, testify, cockroachdb/errors, bubbletea + lipgloss
- Tabular tests when appropriate

## Working with secrets

- `shh set KEY value` to add/update — prefer `shh set KEY -` (stdin) to avoid shell history exposure
- `shh rm KEY` to remove
- `shh edit` to batch edit in `$EDITOR`
- `shh run -- <cmd>` to run with secrets injected
- `shh shell` for interactive shell with secrets
- `shh users add <github-user>` to grant access
- `shh users remove <user>` to revoke (rotates data key)
- NEVER log, print, or echo secret values
- NEVER commit plaintext `.env` files

## Testing

```bash
go test -race ./...
go vet ./...
```

## Security

- Dangerous env vars (`PATH`, `LD_PRELOAD`, `BASH_ENV`, etc.) are blocked at both storage and injection time
- MAC is verified before any decrypt or re-wrap operation
- `SHH_AGE_KEY` and `SHH_PLAINTEXT` are filtered from child process environments
- Security audit prompt lives at `.github/security-review-prompt.md`
