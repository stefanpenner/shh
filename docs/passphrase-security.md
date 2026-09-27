# Passphrase keys

A passphrase goes through argon2id. The 32-byte result is an age X25519 key. shh does not store the phrase. You must remember it.

## Parameters

Do not change these values. A change creates a different key. An old phrase would not open the vault.

| Parameter | Value |
| --- | --- |
| KDF | argon2id |
| Salt | The public bytes of `shh-brainkey-v1` |
| Memory | 256 MiB |
| Time | 3 |
| Threads | 4 |
| Output | 32 bytes |

The salt is not secret. The same phrase yields the same recipient in every project. argon2id makes each guess expensive. It does not hide phrase reuse across projects.

## Threat

`.env.enc` is in git. The attacker has the recipient and the wrapped data key. The attacker can test a guess offline. Security is phrase entropy times this KDF cost.

Use 8 generated diceware words. A 6-word phrase is the practical floor for this cost. Enrollment rejects a phrase shorter than 12 characters. Login does not apply that floor. An offline attack can still succeed against a common 12-character phrase.

The derived key is extractable. If the phrase leaks, treat the key as copied. Change the secret values. Do not only run `shh users remove`.

Pair the passphrase with a hardware key. The failure modes are different. A forgotten phrase and a lost hardware key do not have the same cause.

## Entry

shh does not take the phrase from an argument or from an environment variable. Enrollment prompts twice and does not echo. Login prompts once.

`TrimPassphrase` removes space and format characters before the KDF. Enrollment and login both use that trim. Invisible characters do not create a second key.

A typo at enrollment can make the key unusable. There is no stored copy. Practice the phrase on a schedule.

## Encoding

shh encodes the 32 bytes as an age secret with Bech32, then parses that text with age. The encoder does not branch on the secret. Tests compare it with the age parser.

age clamps the X25519 scalar. Any 32-byte seed is a valid input after that clamp.

## Memory

The phrase and the seed are Go strings. shh does not wipe them. A memory dump during use can contain them.

## What this is not

The derived key is a normal X25519 key. There is no weaker mode to force. The vault does not record that the key came from a phrase.
