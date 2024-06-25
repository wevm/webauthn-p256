import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  hexToBytes,
} from './conversion.js'
import type { Hex } from './types.js'

export type SignParameters = GetCredentialSignRequestOptionsParameters

export type SignReturnType = {
  authenticatorData: Hex
  clientDataJSON: string
}

export async function sign(parameters: SignParameters) {
  const options = getCredentialSignRequestOptions(parameters)
  try {
    const credential = (await window.navigator.credentials.get(
      options,
    )) as PublicKeyCredential
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
  digest: Hex
  /**
   * The relying party identifier to use.
   */
  rpId?: PublicKeyCredentialRequestOptions['rpId'] | undefined
}
export type GetCredentialSignRequestOptionsReturnType = CredentialRequestOptions

export function getCredentialSignRequestOptions(
  parameters: GetCredentialSignRequestOptionsParameters,
): GetCredentialSignRequestOptionsReturnType {
  const { credentialId, digest, rpId = window.location.hostname } = parameters
  const challenge = base64UrlToBytes(bytesToBase64Url(hexToBytes(digest)))
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
  const usignature = new Uint8Array(bytes)
  const rStart = usignature[4] === 0 ? 5 : 4
  const rEnd = rStart + 32
  const sStart = usignature[rEnd + 2] === 0 ? rEnd + 3 : rEnd + 2
  const r = usignature.slice(rStart, rEnd)
  const s = usignature.slice(sStart)
  return {
    r: BigInt(bytesToHex(r)),
    s: BigInt(bytesToHex(s)),
  }
}
