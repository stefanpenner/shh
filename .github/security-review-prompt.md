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
