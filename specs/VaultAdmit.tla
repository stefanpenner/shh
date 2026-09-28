----------------------------- MODULE VaultAdmit -----------------------------
(***************************************************************************
  Write gate. A fresh file can keep a valid MAC and still add an attacker.

  eve: the recipient set is not the trusted set.
  accepted: the operator accepted this set.
  macOk: a partial edit did not break the MAC.
  wrote: a later set wrote the vault.

  Forge keeps macOk true. That is the case Tamper does not cover.
 ***************************************************************************)

EXTENDS TLC

VARIABLES
  eve,
  accepted,
  macOk,
  wrote

vars == <<eve, accepted, macOk, wrote>>

Init ==
  /\ eve = FALSE
  /\ accepted = TRUE
  /\ macOk = TRUE
  /\ wrote = FALSE

Forge ==
  /\ macOk
  /\ accepted
  /\ eve' = TRUE
  /\ accepted' = FALSE
  /\ wrote' = FALSE
  /\ UNCHANGED macOk

Tamper ==
  /\ macOk
  /\ macOk' = FALSE
  /\ wrote' = FALSE
  /\ UNCHANGED <<eve, accepted>>

Accept ==
  /\ ~accepted
  /\ accepted' = TRUE
  /\ UNCHANGED <<eve, macOk, wrote>>

Set ==
  /\ macOk
  /\ accepted
  /\ wrote' = TRUE
  /\ UNCHANGED <<eve, accepted, macOk>>

Next == Forge \/ Tamper \/ Accept \/ Set

Spec == Init /\ [][Next]_vars

WroteImpliesAdmitted == wrote => (macOk /\ accepted)

Inv == WroteImpliesAdmitted

=============================================================================
