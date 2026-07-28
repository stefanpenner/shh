# Formal specs (TLA+)

**Ideal:** smallest state-space with **equivalent or sufficient** capability.  
See `ITERATIONS.md` for the minimize pass.

```bash
tlc specs/RecoveryQR.tla
tlc specs/RecipientVault.tla
```

| Spec | States | Capability |
|------|--------|------------|
| **RecoveryQR** | 5 | enroll+QR, lose daily, scan; QR/session ⇒ recovery enrolled |
| **RecipientVault** | 10 | Alice+optional Bob, MAC tamper, authorized session only |

Go tests/fuzz own crypto, MAC bytes, QR codecs, e2e.
