----------------------------- MODULE RecoveryQR -----------------------------
(***************************************************************************
  Recovery QR core — minimized state-space, sufficient capability.

  Capability kept:
    - enroll recovery + emit QR in one step
    - lose daily session
    - scan QR → recovery session
    - QR only if recovery enrolled
    - recovery session only if recovery enrolled

  Dropped (Go tests cover / not needed for this core):
    - remove daily, paste vs scan, crypto bits, vaultOpen bookkeeping
 ***************************************************************************)

EXTENDS TLC

CONSTANTS Daily, Recovery, None
ASSUME Daily # Recovery /\ Daily # None /\ Recovery # None

VARIABLES
  hasRecovery,  \* recovery is a vault recipient
  qrReady,      \* paper/QR frozen
  session       \* None | Daily | Recovery

vars == <<hasRecovery, qrReady, session>>

TypeOK ==
  /\ hasRecovery \in BOOLEAN
  /\ qrReady \in BOOLEAN
  /\ session \in {None, Daily, Recovery}
  /\ qrReady => hasRecovery
  /\ session = Recovery => hasRecovery

\* Safety
QRImpliesRecovery == qrReady => hasRecovery
RecoverySessionImpliesEnrolled == session = Recovery => hasRecovery
\* Daily is always a recipient in this core (revoke-daily is out of scope)

Inv == TypeOK /\ QRImpliesRecovery /\ RecoverySessionImpliesEnrolled

Init ==
  /\ hasRecovery = FALSE
  /\ qrReady = FALSE
  /\ session = Daily

GenerateEmitQR ==
  /\ ~hasRecovery
  /\ hasRecovery' = TRUE
  /\ qrReady' = TRUE
  /\ UNCHANGED session

LoseDaily ==
  /\ session = Daily
  /\ session' = None
  /\ UNCHANGED <<hasRecovery, qrReady>>

ScanQR ==
  /\ qrReady
  /\ hasRecovery
  /\ session' = Recovery
  /\ UNCHANGED <<hasRecovery, qrReady>>

Next == GenerateEmitQR \/ LoseDaily \/ ScanQR

Spec == Init /\ [][Next]_vars

=============================================================================
