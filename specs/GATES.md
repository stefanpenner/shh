# Gates

Generated modules are the policy. Edit the `.tla`, then run `specgen`. Do not edit `spec.go`.

| Gate | Module | Product call | TLC |
| --- | --- | --- | --- |
| Write | `vaultadmit.Decide` | `shh set`, `shh edit`, `shh rm`, `shh encrypt` | `VaultAdmit` 8 states |
| Merge | `recipientmerge.Decide` | `TryAutoResolve`, `shh merge` | `RecipientMerge` 3 states |

`differs` means the recipient set is not the `HEAD` set. `equal` means both merge sides list the same recipients. `Decide` starts at `Init` on every call.

`Tamper` stays in `VaultAdmit` for TLC. Decrypt failure returns before `Decide`.
