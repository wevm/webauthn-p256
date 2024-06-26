import { numberToBytesBE } from '@noble/curves/abstract/utils'
import type { Hex, PublicKey } from './types.js'
import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToCryptoKey,
  bytesToHex,
  cryptoKeyToBytes,
  hexToBytes,
} from './utils.js'

export type ParseCredentialPublicKeyOptions = {
  compressed?: boolean | undefined
}

export async function parseCredentialPublicKey(
  cPublicKey: ArrayBuffer,
  options: ParseCredentialPublicKeyOptions = {},
): Promise<PublicKey> {
  const { compressed } = options
  const base64Url = bytesToBase64Url(new Uint8Array(cPublicKey))
  const bytes = base64UrlToBytes(base64Url)
  const cryptoKey = await bytesToCryptoKey(bytes)
  const publicKey = await cryptoKeyToBytes(cryptoKey)
  const result = (() => {
    if (compressed) return publicKey.slice(1)
    return publicKey
  })()
  return parsePublicKey(result)
}

export function parsePublicKey(publicKey: Hex | Uint8Array): PublicKey {
  const bytes =
    typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey
  const offset = bytes.length === 65 ? 1 : 0
  const x = bytes.slice(offset, 32 + offset)
  const y = bytes.slice(32 + offset, 64 + offset)
  return {
    ...(bytes.length === 65 ? { prefix: bytes[0] } : {}),
    x: BigInt(bytesToHex(x)),
    y: BigInt(bytesToHex(y)),
  }
}

export type SerializePublicKeyOptions<to extends 'hex' | 'bytes' = 'hex'> = {
  compressed?: boolean | undefined
  to?: to | 'bytes' | 'hex' | undefined
}

export function serializePublicKey<to extends 'hex' | 'bytes' = 'hex'>(
  publicKey: PublicKey,
  options: SerializePublicKeyOptions<to> = {},
): to extends 'hex' ? Hex : Uint8Array {
  const { compressed = false, to = 'hex' } = options
  const result = Uint8Array.from([
    ...(publicKey.prefix && !compressed ? [publicKey.prefix] : []),
    ...numberToBytesBE(publicKey.x, 32),
    ...numberToBytesBE(publicKey.y, 32),
  ])
  return (to === 'hex' ? bytesToHex(result) : result) as any
}
