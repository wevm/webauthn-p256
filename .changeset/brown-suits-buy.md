---
"webauthn-p256": patch
---

**Breaking:** 

- Serialized `publicKey` (hex string) on the return value of `createCredential`.
- Serialized `signature` (hex string) on the return value of `sign`.
- Modified `webauthn.typeIndex` and `webauthn.challengeIndex` to return `number` instead of `bigint`.
- `verify` now expects a serialized `signature` and `publicKey`.
