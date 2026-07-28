# TLA+ minimize × 10 (shh)

Rule: **smallest state-space with equivalent or sufficient capability.**

Baseline → final (this pass):

| Spec | Before | After |
|------|--------|-------|
| RecoveryQR | 7 states, depth 4 | **5 states, depth 3** |
| RecipientVault | 39 states, depth 8 | **12 states, depth 4** (target) |

## Iterations

| # | Change | Capability kept? |
|---|--------|------------------|
| 1 | Drop `Eve` from vault model | Yes — honest recipients only |
| 2 | Drop `Logout` as separate if covered by ClearSession | Yes |
| 3 | Drop dual `generation`+`macGen` → single `macOk` | Yes — tamper still kills decrypt predicate |
| 4 | Drop `Decrypt`/`DecryptFail`/`secretsOK` bookkeeping | Yes — `CanDecrypt` operator |
| 5 | Drop `MaxGen` / Nat bounds | Yes — no counters |
| 6 | Recipients set → `hasBob` boolean (+ implicit Alice) | Yes — two-person core sufficient |
| 7 | RecoveryQR: drop `RemoveDaily` | Yes — recovery path doesn't need revoke-daily |
| 8 | RecoveryQR: `recipients` set → `hasRecovery` boolean | Yes |
| 9 | TypeOK folds QR/session implications (no extra inv noise) | Yes |
| 10 | Document: Go owns crypto/QR bits; TLA owns access sequencing only | Yes |

## What we refuse to drop

- RecoveryQR: `qrReady ⇒ hasRecovery`, `session=Recovery ⇒ hasRecovery`, lose daily, scan QR
- RecipientVault: add/remove Bob, tamper MAC, session never Bob unless enrolled

## Verify

```bash
tlc specs/RecoveryQR.tla
tlc specs/RecipientVault.tla
go test ./...
```
