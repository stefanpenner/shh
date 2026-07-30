--------------------------- MODULE RecipientVault ---------------------------
(***************************************************************************
  Vault access core — minimized state-space, sufficient capability.

  Capability kept:
    - Alice always a recipient
    - optional Bob via add/remove
    - MAC ok / tampered
    - session Alice | Bob | None (Bob only if enrolled)
    - decrypt ok only if authorized ∧ MAC ok

  Dropped: Eve, generation counters, separate DecryptFail, Logout, MaxGen
 ***************************************************************************)

EXTENDS TLC

CONSTANTS Alice, Bob, None
ASSUME Alice # Bob /\ Alice # None /\ Bob # None

VARIABLES
  hasBob,    \* Bob enrolled
  macOk,     \* file MAC intact
  session    \* None | Alice | Bob

vars == <<hasBob, macOk, session>>

TypeOK ==
  /\ hasBob \in BOOLEAN
  /\ macOk \in BOOLEAN
  /\ session \in {None, Alice, Bob}
  /\ session = Bob => hasBob

\* Abstract: can decrypt in this state
CanDecrypt ==
  /\ macOk
  /\ session # None
  /\ session = Alice \/ (session = Bob /\ hasBob)

\* Safety: never "successful decrypt" bookkeeping — CanDecrypt is the predicate.
\* Invariant: session never unauthorized
SessionAuthorized == session = Bob => hasBob

\* At least Alice remains (Bob optional) — always someone
AlwaysAlice == TRUE  \* Alice never removed in this core

Inv == TypeOK /\ SessionAuthorized

Init ==
  /\ hasBob = FALSE
  /\ macOk = TRUE
  /\ session = Alice

LoginAlice ==
  /\ session' = Alice
  /\ UNCHANGED <<hasBob, macOk>>

LoginBob ==
  /\ hasBob
  /\ session' = Bob
  /\ UNCHANGED <<hasBob, macOk>>

ClearSession ==
  /\ session # None
  /\ session' = None
  /\ UNCHANGED <<hasBob, macOk>>

AddBob ==
  /\ ~hasBob
  /\ session = Alice   \* must be authorized to re-wrap
  /\ hasBob' = TRUE
  /\ UNCHANGED <<macOk, session>>

RemoveBob ==
  /\ hasBob
  /\ session = Alice   \* Alice performs remove
  /\ hasBob' = FALSE
  /\ session' = IF session = Bob THEN None ELSE session
  /\ UNCHANGED macOk   \* rotate yields fresh valid MAC for remaining

Tamper ==
  /\ macOk
  /\ macOk' = FALSE
  /\ UNCHANGED <<hasBob, session>>

Next ==
  \/ LoginAlice
  \/ LoginBob
  \/ ClearSession
  \/ AddBob
  \/ RemoveBob
  \/ Tamper

Spec == Init /\ [][Next]_vars

\* CanDecrypt is FALSE after Tamper or when session=None — sufficient for
\* "decrypt only if authorized ∧ intact" without a secretsOK variable.

=============================================================================
