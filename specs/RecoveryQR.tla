----------------------------- MODULE RecoveryQR -----------------------------
(***************************************************************************
  Minimal recovery-QR core for shh (Ring 0).

  Irreducible properties:
    1. QR exists only after recovery is a vault recipient
    2. Scan installs Recovery into the session
    3. Session can use the vault only if it is a recipient
    4. Vault never has zero recipients

  CLI mapping (one GenerateEmitQR ≈ users add --name recovery --qr):
    LoseDaily     ≈ dead Mac / wiped keyring
    ScanQR        ≈ login --qr-file  (paste SHH_AGE_KEY is the same abstract step)

  Crypto / PNG codecs are out of scope — Go tests own fidelity of bits.
 ***************************************************************************)

EXTENDS TLC

CONSTANTS Daily, Recovery, None

ASSUME Daily # Recovery /\ Daily # None /\ Recovery # None

VARIABLES
  recipients,  \* authorized identities (non-empty subset of {Daily, Recovery})
  qrReady,     \* TRUE once recovery secret has been frozen into a QR/paper payload
  session      \* who is logged in: None | Daily | Recovery

vars == <<recipients, qrReady, session>>

TypeOK ==
  /\ recipients \subseteq {Daily, Recovery}
  /\ recipients # {}
  /\ qrReady \in BOOLEAN
  /\ session \in {None, Daily, Recovery}

\* --- Safety (the important things) ----------------------------------------

\* Never lock yourself out of the vault at the recipient layer
AlwaysSomeRecipient == recipients # {}

\* QR implies recovery was enrolled (can't print a recovery QR for nothing)
QRImpliesRecipient == qrReady => Recovery \in recipients

\* Logged-in identity must be authorized to count as "can decrypt"
\* (abstract: decrypt succeeds iff session \in recipients)
SessionAuthorizedWhenPresent ==
  session # None => session \in recipients

Inv ==
  /\ TypeOK
  /\ AlwaysSomeRecipient
  /\ QRImpliesRecipient
  /\ SessionAuthorizedWhenPresent

\* --- Actions --------------------------------------------------------------

Init ==
  /\ recipients = {Daily}
  /\ qrReady = FALSE
  /\ session = Daily

\* Mint recovery recipient and emit QR in one step (matches users add --qr).
GenerateEmitQR ==
  /\ Recovery \notin recipients
  /\ recipients' = recipients \cup {Recovery}
  /\ qrReady' = TRUE
  /\ UNCHANGED session

\* Dead Mac / cleared keyring
LoseDaily ==
  /\ session = Daily
  /\ session' = None
  /\ UNCHANGED <<recipients, qrReady>>

\* Paper/QR/1Password recovery login
ScanQR ==
  /\ qrReady
  /\ Recovery \in recipients
  /\ session' = Recovery
  /\ UNCHANGED <<recipients, qrReady>>

\* Drop daily recipient after recovery exists (still ≥1 recipient)
RemoveDaily ==
  /\ Daily \in recipients
  /\ Recovery \in recipients
  /\ recipients' = recipients \ {Daily}
  /\ session' = IF session = Daily THEN None ELSE session
  /\ UNCHANGED qrReady

Next ==
  \/ GenerateEmitQR
  \/ LoseDaily
  \/ ScanQR
  \/ RemoveDaily

Spec == Init /\ [][Next]_vars

=============================================================================
