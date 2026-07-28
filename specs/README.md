# Formal specs (TLA+)

Small decision cores for shh safety. Check with:

```bash
tlc specs/RecoveryQR.tla
tlc specs/RecipientVault.tla
```

| Spec | What it proves | States (approx) |
|---|---|---|
| **RecoveryQR** | QR recovery: emit ⇒ recovery enrolled; session authorized; never empty recipients | 7 |
| **RecipientVault** | Add/remove recipients, MAC tamper, decrypt only if authorized | ~39 (MaxGen=2) |

Crypto bit fidelity lives in Go tests/fuzz (`internal/crypto`, `internal/qr`, `internal/encfile`).
