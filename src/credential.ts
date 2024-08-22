import { keccak_256 } from '@noble/hashes/sha3'
import { toBytes } from '@noble/hashes/utils'

import {
  exportPublicKey,
  parseCredentialPublicKey,
  serializePublicKey,
} from './publicKey.js'
import type {
  Credential,
  Hash,
  OneOf,
  P256Credential,
  Prettify,
  PublicKeyCredential,
  PublicKeyCredentialCreationOptions,
} from './types.js'
import {
  authData,
  base64UrlToBytes,
  concatBytes,
  formatCryptoKeySignature,
  getClientDataJSON,
  sha256,
} from './utils.js'

// Challenge for credential creation – random 16 bytes.
export const createChallenge = Uint8Array.from([
  105, 171, 180, 181, 160, 222, 75, 198, 42, 42, 32, 31, 141, 37, 186, 233,
])

export type CreateCredentialParameters = GetCredentialCreationOptionsParameters

export type CreateCredentialReturnType<T> = Prettify<P256Credential<T>>

/**
 * Creates a new credential, which can be stored and later used for signing.
 *
 * @example
 * ```ts
 * const credential = await createCredential({ name: 'Example' })
 * ```
 */
export async function createCredential<T extends CreateCredentialParameters>(
  parameters: T,
): Promise<CreateCredentialReturnType<T>> {
  if (parameters.type === 'webauthn') {
    const {
      createFn = window.navigator.credentials.create.bind(
        window.navigator.credentials,
      ),
      type,
      ...rest
    } = parameters
    const options = getCredentialCreationOptions(rest)
    try {
      const credential = (await createFn(options)) as PublicKeyCredential
      if (!credential) throw new Error('credential creation failed.')
      const publicKey = await parseCredentialPublicKey(
        new Uint8Array((credential.response as any).getPublicKey()),
      )
      return {
        id: credential.id,
        publicKey: serializePublicKey(publicKey, { compressed: true }),
        raw: credential,
      } as P256Credential<T>
    } catch (error) {
      throw new Error('webautn credential creation failed.', { cause: error })
    }
  }
  try {
    const { publicKey, privateKey } = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    )
    const exportedPublicKey = await exportPublicKey(publicKey)
    return {
      publicKey: exportedPublicKey,
      privateKey,
      sign: async (hash: Hash) => {
        const clientDataJSON = getClientDataJSON(hash)
        const clientDataJSONHash = sha256(
          base64UrlToBytes(clientDataJSON),
          'bytes',
        )

        const webauthnHash = concatBytes([authData, clientDataJSONHash])
        const signature = await crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          privateKey,
          webauthnHash,
        )

        return formatCryptoKeySignature({ signature, clientDataJSON })
      },
    } as unknown as P256Credential<T>
  } catch (error) {
    throw new Error('cryptoKey credential creation failed.', { cause: error })
  }
}

export type WebautnCredentialCreationOptionsParameters = {
  type: 'webauthn'
  /**
   * A string specifying the relying party's preference for how the attestation statement
   * (i.e., provision of verifiable evidence of the authenticity of the authenticator and its data)
   * is conveyed during credential creation.
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
   * List of credential IDs to exclude from the creation. This property can be used
   * to prevent creation of a credential if it already exists.
   */
  excludeCredentialIds?: readonly string[] | undefined
  /**
   * List of Web Authentication API credentials to use during creation or authentication.
   */
  extensions?: PublicKeyCredentialCreationOptions['extensions'] | undefined
  /**
   * An object describing the relying party that requested the credential creation
   */
  rp?:
    | {
        id: string
        name: string
      }
    | undefined
  /**
   * A numerical hint, in milliseconds, which indicates the time the calling web app is willing to wait for the creation operation to complete.
   */
  timeout?: PublicKeyCredentialCreationOptions['timeout'] | undefined
} & OneOf<
  | {
      /** Name for the credential (user.name). */
      name: string
    }
  | {
      /**
       * An object describing the user account for which the credential is generated.
       */
      user: {
        displayName?: string
        id?: BufferSource
        name: string
      }
    }
> & {
    createFn?:
      | ((
          options?: CredentialCreationOptions | undefined,
        ) => Promise<Credential | null>)
      | undefined
  }

export type CryptoKeyCreationOptionsParameters = {
  type: 'cryptoKey'
}

export type GetCredentialCreationOptionsParameters =
  | WebautnCredentialCreationOptionsParameters
  | CryptoKeyCreationOptionsParameters

export type GetCredentialCreationOptionsReturnType = CredentialCreationOptions

/**
 * Returns the creation options for a P256 WebAuthn Credential with a Passkey authenticator.
 *
 * @example
 * ```ts
 * const options = getCredentialCreationOptions({ name: 'Example' })
 * const credentials = window.navigator.credentials.create(options)
 * ```
 */
export function getCredentialCreationOptions(
  parameters: Omit<WebautnCredentialCreationOptionsParameters, 'type'>,
): GetCredentialCreationOptionsReturnType {
  const {
    attestation = 'none',
    authenticatorSelection = {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      requireResidentKey: false,
      userVerification: 'required',
    },
    challenge = createChallenge,
    excludeCredentialIds,
    name: name_,
    rp = {
      id: window.location.hostname,
      name: window.document.title,
    },
    user,
    extensions,
  } = parameters
  const name = (user?.name ?? name_)!
  return {
    publicKey: {
      attestation,
      authenticatorSelection,
      challenge,
      ...(excludeCredentialIds
        ? {
            excludeCredentials: excludeCredentialIds?.map((id) => ({
              id: base64UrlToBytes(id),
              type: 'public-key',
            })),
          }
        : {}),
      pubKeyCredParams: [
        {
          type: 'public-key',
          alg: -7, // p256
        },
      ],
      rp,
      user: {
        id: user?.id ?? keccak_256(toBytes(name)),
        name,
        displayName: user?.displayName ?? name,
      },
      extensions,
    },
  } as CredentialCreationOptions
}
