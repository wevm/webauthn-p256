import { secp256r1 } from '@noble/curves/p256'
import { concatBytes, utf8ToBytes } from '@noble/hashes/utils'
import { parsePublicKey } from './publicKey.js'
import type { Hex, WebAuthnSignature } from './types.js'
import { hexToBytes } from './utils.js'

export type VerifyParameters = {
  publicKey: Hex
  signature: WebAuthnSignature
}

export type VerifyReturnType = boolean

export async function verify(
  parameters: VerifyParameters,
): Promise<VerifyReturnType> {
  const { publicKey, signature } = parameters

  const clientDataJSONHash = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      utf8ToBytes(signature.clientDataJSON),
    ),
  )
  const messageHash = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      concatBytes(hexToBytes(signature.authenticatorData), clientDataJSONHash),
    ),
  )

  const recovered_0 = new secp256r1.Signature(signature.r, signature.s)
    .addRecoveryBit(0)
    .recoverPublicKey(messageHash)
  const recovered_1 = new secp256r1.Signature(signature.r, signature.s)
    .addRecoveryBit(1)
    .recoverPublicKey(messageHash)

  const { x, y } = parsePublicKey(publicKey)

  return (
    (recovered_0.x === x && recovered_0.y === y) ||
    (recovered_1.x === x && recovered_1.y === y)
  )
}
