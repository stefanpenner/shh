----------------------------- MODULE RecoveryQR -----------------------------
(***************************************************************************
  Recovery QR lifecycle for shh (Ring 0).

  Models the safety of paper/QR recovery:
    - offline recovery secret is generated once
    - EmitQR freezes that secret into a QR payload
    - DecodeQR recovers the exact secret (fidelity)
    - Login installs the secret into the keyring
    - DecryptVault succeeds only when keyring is an authorized recipient
    - Never remove the last recipient
    - Daily key loss does not destroy recovery if QR still exists

  This is a decision/state-machine core for recovery, not crypto math.
 ***************************************************************************)

EXTENDS Naturals, Sequences, TLC

CONSTANTS
  Daily,       \* daily Mac key identity token
  Recovery,    \* recovery identity token
  None         \* empty / absent

ASSUME Daily # Recovery /\ Daily # None /\ Recovery # None

VARIABLES
  recipients,     \* set of authorized identity tokens
  recoverySecret, \* offline recovery secret (None until generated)
  qrPayload,      \* payload written into QR (None or Recovery)
  keyring,        \* currently logged-in identity (None, Daily, or Recovery)
  vaultOpen       \* whether last decrypt succeeded

vars == <<recipients, recoverySecret, qrPayload, keyring, vaultOpen>>

TypeOK ==
  /\ recipients \subseteq {Daily, Recovery}
  /\ recipients # {}
  /\ recoverySecret \in {None, Recovery}
  /\ qrPayload \in {None, Recovery}
  /\ keyring \in {None, Daily, Recovery}
  /\ vaultOpen \in BOOLEAN

----------------------------------------------------------------------------
\* Safety: decrypt only if keyring is a current recipient
DecryptOnlyIfRecipient ==
  vaultOpen => keyring \in recipients

\* Safety: QR never contains a secret that was not the recovery secret
QROnlyRecovery ==
  qrPayload # None => qrPayload = recoverySecret

\* Safety: always at least one recipient
AlwaysSomeRecipient ==
  recipients # {}

\* Round-trip: after emit+decode path, keyring can become Recovery
\* (expressed operationally via actions; invariant that QR matches secret)
QRFidelity ==
  (qrPayload # None /\ recoverySecret # None) => qrPayload = recoverySecret

----------------------------------------------------------------------------
Init ==
  /\ recipients = {Daily}
  /\ recoverySecret = None
  /\ qrPayload = None
  /\ keyring = Daily
  /\ vaultOpen = FALSE

\* Generate a recovery identity (shh users add --name recovery)
GenerateRecovery ==
  /\ recoverySecret = None
  /\ recoverySecret' = Recovery
  /\ recipients' = recipients \cup {Recovery}
  /\ UNCHANGED <<qrPayload, keyring, vaultOpen>>

\* Emit QR of the recovery secret (shh users add --qr / paper card)
EmitQR ==
  /\ recoverySecret = Recovery
  /\ qrPayload' = recoverySecret
  /\ UNCHANGED <<recipients, recoverySecret, keyring, vaultOpen>>

\* Lose daily key (dead Mac / wiped keyring)
LoseDailyKey ==
  /\ keyring = Daily
  /\ keyring' = None
  /\ vaultOpen' = FALSE
  /\ UNCHANGED <<recipients, recoverySecret, qrPayload>>

\* Scan QR into keyring (shh login --qr-file)
\* Fidelity: only Recovery payload accepted for recovery path
ScanQR ==
  /\ qrPayload = Recovery
  /\ keyring' = qrPayload
  /\ vaultOpen' = FALSE
  /\ UNCHANGED <<recipients, recoverySecret, qrPayload>>

\* Login with SHH_AGE_KEY / pasted recovery secret
LoginRecoverySecret ==
  /\ recoverySecret = Recovery
  /\ keyring' = Recovery
  /\ vaultOpen' = FALSE
  /\ UNCHANGED <<recipients, recoverySecret, qrPayload>>

\* Decrypt vault if authorized
DecryptVault ==
  /\ keyring \in recipients
  /\ vaultOpen' = TRUE
  /\ UNCHANGED <<recipients, recoverySecret, qrPayload, keyring>>

\* Failed decrypt attempt (wrong key / empty keyring)
DecryptFail ==
  /\ keyring \notin recipients
  /\ vaultOpen' = FALSE
  /\ UNCHANGED <<recipients, recoverySecret, qrPayload, keyring>>

\* Remove daily recipient (must keep recovery)
RemoveDaily ==
  /\ Daily \in recipients
  /\ Recovery \in recipients
  /\ recipients' = recipients \ {Daily}
  /\ keyring' = IF keyring = Daily THEN None ELSE keyring
  /\ vaultOpen' = FALSE
  /\ UNCHANGED <<recoverySecret, qrPayload>>

\* Cannot model removing last recipient — that action is absent on purpose.

Next ==
  \/ GenerateRecovery
  \/ EmitQR
  \/ LoseDailyKey
  \/ ScanQR
  \/ LoginRecoverySecret
  \/ DecryptVault
  \/ DecryptFail
  \/ RemoveDaily

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
\* Invariants checked by TLC
Inv ==
  /\ TypeOK
  /\ DecryptOnlyIfRecipient
  /\ QROnlyRecovery
  /\ AlwaysSomeRecipient
  /\ QRFidelity

\* Reachability: dead Mac + QR recovery can still open vault
\* (checked as a temporal property / bait via state constraint in cfg comments)
\* TLC will explore ScanQR after LoseDailyKey after EmitQR after GenerateRecovery.

=============================================================================
