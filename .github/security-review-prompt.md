You are performing an adversarial security audit of this codebase.
This is an encrypted .env management tool using age encryption, SOPS,
and macOS Keychain. It handles private keys, encryption/decryption,
and fetches SSH keys from GitHub.

Perform a thorough security review covering:

1. **Cryptographic issues**: key handling, entropy, side channels,
   timing attacks, key material in memory/logs/temp files
2. **Input validation**: command injection via user inputs, path
   traversal, malformed age keys, dotenv parsing edge cases
3. **Network security**: SSRF via GitHub key fetching, redirect
   handling, TLS verification, response size limits
4. **Secrets management**: key leakage through error messages,
   process arguments visible in `ps`, temp file cleanup races,
   environment variable exposure
5. **Dependency risks**: known CVEs in dependencies, supply chain
   concerns, outdated cryptographic libraries
6. **Race conditions**: TOCTOU in file operations, concurrent
   access to keychain/config files
7. **Privilege escalation**: keychain access controls, file
   permissions on sensitive files

For each finding, provide:
- Severity (Critical/High/Medium/Low/Info)
- Affected file and line numbers
- Description of the vulnerability
- Proof-of-concept or attack scenario
- Recommended fix

Also research recent CVEs in the dependency tree (age, sops,
ssh-to-age, cobra) and flag any that apply.

Be adversarial — think like an attacker targeting this tool.

Finally, audit this prompt itself and propose improvements. We are self healing and evolving.

## Static analysis triage

If static analysis results are appended below, triage every finding:
- **Real issues**: fix the code
- **False positives**: add a `// nolint:rulename` or `// #nosec Gxxx`
  annotation with a brief justification comment on the same line
  explaining why it is safe

The goal is a clean scan — every finding should be either fixed or
annotated so the scan exits 0.

## Fix and open a PR

After completing the audit, combine your own findings with the static
analysis fixes into a single PR:

1. Create a new branch named `security/fix-<short-description>`
2. Apply the fixes, keeping changes minimal and focused
3. Run `go vet ./...` and `go test -race ./...` to verify nothing breaks
4. Run `gosec ./...` and `staticcheck ./...` to confirm a clean scan
5. Commit with a clear message explaining the security issues and fixes
6. Push the branch and open a pull request with:
   - Title prefixed with `security:`
   - Body containing the finding details (severity, description, attack
     scenario) and explanation of each fix
   - Label: `security`

If there are no fixable findings, skip the PR and just report the audit
results. Do not open a PR for Low/Info findings or speculative issues.

