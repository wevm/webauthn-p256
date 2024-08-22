import { sha256 as noble_sha256 } from '@noble/hashes/sha256'
import {
  bytesToHex as bytesToHex_noble,
  hexToBytes as hexToBytes_noble,
} from '@noble/hashes/utils'
import { encodeAbiParameters, stringToHex } from 'viem'
import type { Hash, Hex } from './types.js'

export function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${bytesToHex_noble(bytes)}`
}

export function hexToBytes(value: Hex): Uint8Array {
  return hexToBytes_noble(value.slice(2))
}

export function base64UrlToBytes(base64Url: string): Uint8Array {
  const base64 = base64UrlToBase64(base64Url)
  const utf8 = base64ToUtf8(base64)
  return Uint8Array.from(utf8, (c) => c.charCodeAt(0))
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  const base64 = utf8ToBase64(String.fromCharCode(...bytes))
  return base64ToBase64Url(base64)
}

export function base64UrlToBase64(base64Url: string): string {
  return base64Url.replaceAll('-', '+').replaceAll('_', '/')
}

export function base64ToBase64Url(base64: string): string {
  return base64.replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

export function base64ToUtf8(base64: string): string {
  return atob(base64)
}

export function utf8ToBase64(base64: string): string {
  return btoa(base64)
}

export async function bytesToCryptoKey(bytes: Uint8Array): Promise<any> {
  return await crypto.subtle.importKey(
    'spki',
    bytes,
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
      hash: 'SHA-256',
    },
    true,
    ['verify'],
  )
}

export async function cryptoKeyToBytes(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key))
}

export function isHex(
  value: unknown,
  { strict = true }: { strict?: boolean | undefined } = {},
): value is Hex {
  if (!value) return false
  if (typeof value !== 'string') return false
  return strict ? /^0x[0-9a-fA-F]*$/.test(value) : value.startsWith('0x')
}

export type Sha256Hash<to extends 'hex' | 'bytes'> =
  | (to extends 'bytes' ? Uint8Array : never)
  | (to extends 'hex' ? Hex : never)

export function sha256<to extends 'hex' | 'bytes' = 'hex'>(
  value: Hex | Uint8Array,
  to_?: to | undefined,
): Sha256Hash<to> {
  const to = to_ || 'hex'
  const bytes = noble_sha256(
    isHex(value, { strict: false }) ? hexToBytes(value) : value,
  )
  if (to === 'bytes') return bytes as Sha256Hash<to>
  return bytesToHex(bytes) as Sha256Hash<to>
}

export function concatBytes(values: readonly Uint8Array[]): Uint8Array {
  let length = 0
  for (const arr of values) {
    length += arr.length
  }
  const result = new Uint8Array(length)
  let offset = 0
  for (const arr of values) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

export const authData = (function getAuthData(): Uint8Array {
  const rpBytes = new Uint8Array(Buffer.from(window.location.hostname, 'utf8'))
  const rpIdHash = sha256(rpBytes, 'bytes')
  const flagsBuf = new Uint8Array([5])
  const signCountBuf = new Uint8Array([0, 0, 0, 0])
  return concatBytes([rpIdHash, flagsBuf, signCountBuf])
})()

export function getClientDataJSON(hash: Hash): string {
  const base64UrlHash = bytesToBase64Url(hexToBytes(hash))
  return base64ToBase64Url(
    utf8ToBase64(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: base64UrlHash,
        origin: window.location.origin,
        crossOrigin: false,
      }),
    ),
  )
}

export type HexToBigIntOpts = {
  /** Whether or not the number of a signed representation. */
  signed?: boolean | undefined
  /** Size (in bytes) of the hex value. */
  size?: number | undefined
}

export function hexToBigInt(hex: Hex, opts: HexToBigIntOpts = {}): bigint {
  const { signed } = opts

  const value = BigInt(hex)
  if (!signed) return value

  const size = (hex.length - 2) / 2
  const max = (1n << (BigInt(size) * 8n - 1n)) - 1n
  if (value <= max) return value

  return value - BigInt(`0x${'f'.padStart(size * 2, 'f')}`) - 1n
}

export type FormatCryptoKeySignatureParams = {
  signature: ArrayBuffer
  clientDataJSON: string
}

export function formatCryptoKeySignature({
  signature,
  clientDataJSON,
}: FormatCryptoKeySignatureParams): Hex {
  const signatureBytes = new Uint8Array(signature)
  const r = hexToBigInt(bytesToHex(signatureBytes.slice(0, 32)))
  let s = hexToBigInt(bytesToHex(signatureBytes.slice(32)))
  const n = BigInt(
    '0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551',
  )
  if (s > n / BigInt(2)) {
    s = n - s
  }
  const jsonClientDataUtf8 = base64ToUtf8(base64UrlToBase64(clientDataJSON))
  const challengeIndex = jsonClientDataUtf8.indexOf('"challenge":')
  const typeIndex = jsonClientDataUtf8.indexOf('"type":')

  const webauthnSignature = encodeAbiParameters(
    [
      {
        components: [
          {
            name: 'authenticatorData',
            type: 'bytes',
          },
          { name: 'clientDataJSON', type: 'bytes' },
          { name: 'challengeIndex', type: 'uint256' },
          { name: 'typeIndex', type: 'uint256' },
          {
            name: 'r',
            type: 'uint256',
          },
          {
            name: 's',
            type: 'uint256',
          },
        ],
        name: 'WebAuthnAuth',
        type: 'tuple',
      },
    ],
    [
      {
        authenticatorData: bytesToHex(authData),
        clientDataJSON: stringToHex(jsonClientDataUtf8),
        challengeIndex: BigInt(challengeIndex),
        typeIndex: BigInt(typeIndex),
        r,
        s,
      },
    ],
  )

  return webauthnSignature
}
