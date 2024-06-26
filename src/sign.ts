import type { Credential, Hex, WebAuthnSignature } from './types.js'
import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  hexToBytes,
} from './utils.js'

export type SignParameters = GetCredentialSignRequestOptionsParameters & {
  getFn?: (
    options?: CredentialRequestOptions | undefined,
  ) => Promise<Credential | null>
}

export type SignReturnType = WebAuthnSignature

export async function sign(
  parameters: SignParameters,
): Promise<SignReturnType> {
  const { getFn = window.navigator.credentials.get, ...rest } = parameters
  const options = getCredentialSignRequestOptions(rest)
  try {
    const credential = (await getFn(options)) as PublicKeyCredential
    if (!credential) throw new Error('credential request failed.')
    const response = credential.response as AuthenticatorAssertionResponse

    const clientDataJSON = String.fromCharCode(
      ...new Uint8Array(response.clientDataJSON),
    )
    const challengeIndex = BigInt(clientDataJSON.indexOf('"challenge"'))
    const typeIndex = BigInt(clientDataJSON.indexOf('"type"'))

    const { r, s } = parseAsn1Signature(
      base64UrlToBytes(bytesToBase64Url(new Uint8Array(response.signature))),
    )

    return {
      authenticatorData: bytesToHex(new Uint8Array(response.authenticatorData)),
      clientDataJSON,
      challengeIndex,
      typeIndex,
      r,
      s,
    }
  } catch (error) {
    throw new Error('credential request failed.', { cause: error })
  }
}

export type GetCredentialSignRequestOptionsParameters = {
  credentialId?: string | undefined
  hash: Hex
  /**
   * The relying party identifier to use.
   */
  rpId?: PublicKeyCredentialRequestOptions['rpId'] | undefined
}
export type GetCredentialSignRequestOptionsReturnType = CredentialRequestOptions

export function getCredentialSignRequestOptions(
  parameters: GetCredentialSignRequestOptionsParameters,
): GetCredentialSignRequestOptionsReturnType {
  const { credentialId, hash, rpId = window.location.hostname } = parameters
  const challenge = base64UrlToBytes(bytesToBase64Url(hexToBytes(hash)))
  return {
    publicKey: {
      ...(credentialId
        ? {
            allowCredentials: [
              {
                id: base64UrlToBytes(credentialId),
                type: 'public-key',
              },
            ],
          }
        : {}),
      challenge,
      rpId,
      userVerification: 'required',
    },
  }
}

function parseAsn1Signature(bytes: Uint8Array) {
  const r_start = bytes[4] === 0 ? 5 : 4
  const r_end = r_start + 32
  const s_start = bytes[r_end + 2] === 0 ? r_end + 3 : r_end + 2

  const r = BigInt(bytesToHex(bytes.slice(r_start, r_end)))
  const s = BigInt(bytesToHex(bytes.slice(s_start)))
  const n = BigInt(
    '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
  )
  return {
    r,
    s: s > n / 2n ? n - s : s,
  }
}
