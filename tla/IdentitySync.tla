---- MODULE IdentitySync ----
\* One iCloud slot for the person. The unix name is not part of the key.
\*
\* cloud:
\*   none     no iCloud item
\*   a, b     an age identity. This is the identity a signed get returns.
\*   revoked  logout. A signed get clears the login item and returns none.
\*
\* local[m]:
\*   none     no login-keychain item on Mac m
\*   a, b     cached identity. Signed get replaces it from cloud.
\*            Offline get may still return it.
\*
\* A signed store writes cloud, then the login item.
\* A crash can leave cloud new and the login item old. The next signed get repairs it.
\* An offline store or logout changes nothing and reports failure.

EXTENDS TLC

CONSTANTS Machines, none, a, b, revoked

Ids == {none, a, b}
Cloud == {none, a, b, revoked}

VARIABLES local, cloud, lastOp, lastMac, lastOk, lastVal

TypeOK ==
    /\ local \in [Machines -> Ids]
    /\ cloud \in Cloud
    /\ lastOp \in {"init", "store", "get", "get-off", "delete", "delete-off"}
    /\ lastMac \in Machines
    /\ lastOk \in BOOLEAN
    /\ lastVal \in Ids

Init ==
    /\ local = [m \in Machines |-> none]
    /\ cloud = none
    /\ lastOp = "init"
    /\ lastMac = CHOOSE m \in Machines : TRUE
    /\ lastOk = TRUE
    /\ lastVal = none

Store(m, id) ==
    /\ id \in {a, b}
    /\ cloud' = id
    /\ local' = [local EXCEPT ![m] = id]
    /\ lastOp' = "store"
    /\ lastMac' = m
    /\ lastOk' = TRUE
    /\ lastVal' = id

\* Cloud write landed. Login write did not. Caller sees failure.
StoreCrash(m, id) ==
    /\ id \in {a, b}
    /\ cloud' = id
    /\ lastOp' = "store"
    /\ lastMac' = m
    /\ lastOk' = FALSE
    /\ lastVal' = id
    /\ UNCHANGED local

\* Offline or iCloud refused the write. Neither copy changes.
StoreOffline(m, id) ==
    /\ id \in {a, b}
    /\ lastOp' = "store"
    /\ lastMac' = m
    /\ lastOk' = FALSE
    /\ lastVal' = id
    /\ UNCHANGED <<local, cloud>>

GetSigned(m) ==
    /\ lastOp' = "get"
    /\ lastMac' = m
    /\ \/ /\ cloud \in {a, b}
          /\ local' = [local EXCEPT ![m] = cloud]
          /\ lastOk' = TRUE
          /\ lastVal' = cloud
          /\ UNCHANGED cloud
       \/ /\ cloud = revoked
          /\ local' = [local EXCEPT ![m] = none]
          /\ lastOk' = FALSE
          /\ lastVal' = none
          /\ UNCHANGED cloud
       \/ /\ cloud = none
          /\ local[m] \in {a, b}
          /\ cloud' = local[m]
          /\ lastOk' = TRUE
          /\ lastVal' = local[m]
          /\ UNCHANGED local
       \/ /\ cloud = none
          /\ local[m] = none
          /\ lastOk' = FALSE
          /\ lastVal' = none
          /\ UNCHANGED <<local, cloud>>

GetOffline(m) ==
    /\ lastOp' = "get-off"
    /\ lastMac' = m
    /\ lastVal' = local[m]
    /\ lastOk' = (local[m] # none)
    /\ UNCHANGED <<local, cloud>>

Delete(m) ==
    /\ lastOp' = "delete"
    /\ lastMac' = m
    /\ \/ /\ cloud = none /\ local[m] = none
          /\ lastOk' = FALSE
          /\ lastVal' = none
          /\ UNCHANGED <<local, cloud>>
       \/ /\ cloud = revoked /\ local[m] = none
          /\ lastOk' = FALSE
          /\ lastVal' = none
          /\ UNCHANGED <<local, cloud>>
       \/ /\ cloud \in {a, b} \/ local[m] \in {a, b} \/ (cloud = revoked /\ local[m] \in {a, b})
          /\ cloud' = revoked
          /\ local' = [local EXCEPT ![m] = none]
          /\ lastOk' = TRUE
          /\ lastVal' = none

DeleteOffline(m) ==
    /\ lastOp' = "delete-off"
    /\ lastMac' = m
    /\ lastOk' = FALSE
    /\ lastVal' = none
    /\ UNCHANGED <<local, cloud>>

Next ==
    \/ \E m \in Machines, id \in {a, b} : Store(m, id)
    \/ \E m \in Machines, id \in {a, b} : StoreCrash(m, id)
    \/ \E m \in Machines, id \in {a, b} : StoreOffline(m, id)
    \/ \E m \in Machines : GetSigned(m)
    \/ \E m \in Machines : GetOffline(m)
    \/ \E m \in Machines : Delete(m)
    \/ \E m \in Machines : DeleteOffline(m)

\* A successful store published one identity and cached it on that Mac.
StorePublishes ==
    lastOp = "store" /\ lastOk =>
        cloud = lastVal /\ local[lastMac] = lastVal /\ lastVal \in {a, b}

\* A login item never exists while cloud has no item.
\* Logout uses revoked, so the other Mac's cache is not an orphan publish.
NoOrphanLocal ==
    \A m \in Machines : local[m] \in {a, b} => cloud # none

\* Signed get returns the cloud identity, or nothing when cloud is empty or revoked.
SignedGet ==
    lastOp = "get" =>
        /\ cloud \in {a, b} => lastOk /\ lastVal = cloud /\ local[lastMac] = cloud
        /\ cloud = revoked => ~lastOk /\ local[lastMac] = none /\ lastVal = none
        /\ cloud = none => ~lastOk /\ local[lastMac] = none /\ lastVal = none

\* Successful logout revokes the one cloud slot and clears this Mac.
LogoutRevokes ==
    lastOp = "delete" /\ lastOk =>
        cloud = revoked /\ local[lastMac] = none

\* Offline logout cannot report success.
OfflineLogoutFails ==
    lastOp = "delete-off" => ~lastOk

====
