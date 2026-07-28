--------------------------- MODULE RecipientVault ---------------------------
(***************************************************************************
  Minimal vault access core for shh (.env.enc recipients + data key).

  1. Decrypt succeeds only when session ∈ recipients and MAC intact
  2. Never empty recipients
  3. Remove rotates generation (old data key conceptually dead)
  4. Add does not rotate generation (re-wrap only)
  5. Tamper breaks MAC (macGen ≠ generation) → decrypt fails

  Go owns age/MAC bytes; this owns access-control sequencing.
 ***************************************************************************)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Alice, Bob, Eve, None, MaxGen

ASSUME
  /\ Cardinality({Alice, Bob, Eve, None}) = 4
  /\ MaxGen \in Nat

VARIABLES
  recipients,
  generation,   \* 0..MaxGen
  session,
  macGen,       \* equals generation when file intact
  secretsOK

vars == <<recipients, generation, session, macGen, secretsOK>>

Gens == 0..MaxGen

TypeOK ==
  /\ recipients \subseteq {Alice, Bob, Eve}
  /\ recipients # {}
  /\ generation \in Gens
  /\ session \in {Alice, Bob, Eve, None}
  /\ macGen \in Gens
  /\ secretsOK \in BOOLEAN

AlwaysSomeRecipient == recipients # {}

DecryptOnlyIfAuthorized ==
  secretsOK => (session \in recipients /\ macGen = generation)

Inv ==
  /\ TypeOK
  /\ AlwaysSomeRecipient
  /\ DecryptOnlyIfAuthorized

Init ==
  /\ recipients = {Alice}
  /\ generation = 0
  /\ session = Alice
  /\ macGen = 0
  /\ secretsOK = FALSE

Login(id) ==
  /\ id \in {Alice, Bob}
  /\ session' = id
  /\ secretsOK' = FALSE
  /\ UNCHANGED <<recipients, generation, macGen>>

Logout ==
  /\ session # None
  /\ session' = None
  /\ secretsOK' = FALSE
  /\ UNCHANGED <<recipients, generation, macGen>>

AddBob ==
  /\ session = Alice
  /\ Bob \notin recipients
  /\ recipients' = recipients \cup {Bob}
  /\ secretsOK' = FALSE
  /\ UNCHANGED <<generation, session, macGen>>

RemoveBob ==
  /\ session \in recipients
  /\ Bob \in recipients
  /\ Cardinality(recipients) > 1
  /\ generation < MaxGen
  /\ recipients' = recipients \ {Bob}
  /\ generation' = generation + 1
  /\ macGen' = generation + 1
  /\ secretsOK' = FALSE
  /\ session' = IF session = Bob THEN None ELSE session

Decrypt ==
  /\ session \in recipients
  /\ macGen = generation
  /\ secretsOK' = TRUE
  /\ UNCHANGED <<recipients, generation, session, macGen>>

DecryptFail ==
  /\ ~(session \in recipients /\ macGen = generation)
  /\ secretsOK' = FALSE
  /\ UNCHANGED <<recipients, generation, session, macGen>>

\* Tamper: MAC no longer matches current generation (bounded)
Tamper ==
  /\ generation < MaxGen
  /\ macGen = generation
  /\ macGen' = generation + 1
  /\ secretsOK' = FALSE
  /\ UNCHANGED <<recipients, generation, session>>

Next ==
  \/ \E id \in {Alice, Bob}: Login(id)
  \/ Logout
  \/ AddBob
  \/ RemoveBob
  \/ Decrypt
  \/ DecryptFail
  \/ Tamper

Spec == Init /\ [][Next]_vars

=============================================================================
