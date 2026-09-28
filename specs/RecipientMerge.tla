-------------------------- MODULE RecipientMerge ---------------------------
(***************************************************************************
  Merge gate. A write is allowed only when both sides list the same recipients.

  setsEqual: ours and theirs have the same recipient map.
  wrote: the merge wrote a vault.
 ***************************************************************************)

EXTENDS TLC

VARIABLES
  setsEqual,
  wrote

vars == <<setsEqual, wrote>>

Init ==
  /\ setsEqual = FALSE
  /\ wrote = FALSE

NoteEqual ==
  /\ ~setsEqual
  /\ setsEqual' = TRUE
  /\ UNCHANGED wrote

Merge ==
  /\ setsEqual
  /\ wrote' = TRUE
  /\ UNCHANGED setsEqual

Next == NoteEqual \/ Merge

Spec == Init /\ [][Next]_vars

WroteImpliesEqual == wrote => setsEqual

Inv == WroteImpliesEqual

=============================================================================
