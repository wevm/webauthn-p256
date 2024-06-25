import { keccak_256 } from '@noble/hashes/sha3'
import { toBytes } from '@noble/hashes/utils'

export type CreateCredentialParameters = {
  /**
   * A string specifying the relying party's preference for how the attestation statement
   * (i.e., provision of verifiable evidence of the authenticity of the authenticator and
   * its data) is conveyed during credential creation.
   */
  attestation?: PublicKeyCredentialCreationOptions['attestation'] | undefined
  /**
   * An object whose properties are criteria used to filter out the potential authenticators
   * for the credential creation operation.
   */
  authenticatorSelection?:
    | PublicKeyCredentialCreationOptions['authenticatorSelection']
    | undefined
  /**
   * An `ArrayBuffer`, `TypedArray`, or `DataView` used as a cryptographic challenge.
   */
  challenge?: PublicKeyCredentialCreationOptions['challenge'] | undefined
  /**
   * An object describing the relying party that requested the credential creation
   */
  relyingParty?:
    | {
        id: string
        name: string
      }
    | undefined
  /**
   * A numerical hint, in milliseconds, which indicates the time the calling web app is willing to wait for the creation operation to complete.
   */
  timeout?: PublicKeyCredentialCreationOptions['timeout'] | undefined
  /**
   * An object describing the user account for which the credential is generated.
   */
  user: {
    displayName?: string
    id?: BufferSource
    name: string
  }
}

export type CreateCredentialReturnType = Credential

// Challenge for credential creation – random 16 bytes.
const createChallenge = Uint8Array.from([
  105, 171, 180, 181, 160, 222, 75, 198, 42, 42, 32, 31, 141, 37, 186, 233,
])

export async function createCredential(
  parameters: CreateCredentialParameters,
): Promise<CreateCredentialReturnType> {
  const {
    attestation = 'none',
    authenticatorSelection = {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      requireResidentKey: false,
      userVerification: 'required',
    },
    challenge = createChallenge,
    relyingParty: rp = {
      id: window.location.hostname,
      name: window.document.title,
    },
    timeout,
    user,
  } = parameters
  const credential = await window.navigator.credentials.create({
    publicKey: {
      attestation,
      authenticatorSelection,
      challenge,
      pubKeyCredParams: [
        {
          type: 'public-key',
          alg: -7, // p256
        },
      ],
      rp,
      user: {
        id: user.id ?? keccak_256(toBytes(user.name)),
        name: user.name,
        displayName: user.displayName ?? user.name,
      },
      ...(timeout ? { timeout } : {}),
    },
  })
  if (!credential) throw new Error('credential creation failed.')
  return credential
}
