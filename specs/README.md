# Formal specs (TLA+)

Smallest state space with the same policy. See `ITERATIONS.md` for the older minimize pass. See `GATES.md` for the generated gates.

```bash
tlc specs/RecoveryQR.tla
tlc specs/RecipientVault.tla
tlc specs/VaultAdmit.tla
tlc specs/RecipientMerge.tla
specgen -o internal/vaultadmit -p vaultadmit specs/VaultAdmit.tla
specgen -o internal/recipientmerge -p recipientmerge specs/RecipientMerge.tla
```

| Spec | States | Capability |
|------|--------|------------|
| **RecoveryQR** | 5 | Enroll and scan. A recovery session requires enrollment. |
| **RecipientVault** | 10 | Alice, optional Bob, MAC tamper, authorized session only. |
| **VaultAdmit** | 8 | A forge keeps a valid MAC. A write requires an accepted set. |
| **RecipientMerge** | 3 | a merge write requires equal recipient sets |

Go calls the generated `Can*` guards. It does not restate them. `go test` runs `conform` on those traces when `conform` is on `PATH`.
