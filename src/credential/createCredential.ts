import { parseCredentialPublicKey } from '../utils/publicKey.js'
import {
  type GetCredentialCreationOptionsParameters,
  getCredentialCreationOptions,
} from './getCredentialCreationOptions.js'

export type CreateCredentialParameters = GetCredentialCreationOptionsParameters
export type CreateCredentialReturnType = {
  id: PublicKeyCredential['id']
  publicKey: string
  publicKeyCompressed: string
}

/**
 * Creates a new credential, which can be stored and later used for signing.
 *
 * @example
 * ```ts
 * const credential = await createCredential({ name: 'Example' })
 * ```
 */
export async function createCredential(
  parameters: CreateCredentialParameters,
): Promise<CreateCredentialReturnType> {
  const options = getCredentialCreationOptions(parameters)
  try {
    const credential = (await window.navigator.credentials.create(
      options,
    )) as PublicKeyCredential
    if (!credential) throw new Error('credential creation failed.')
    const cPublicKey = new Uint8Array(
      (credential.response as any).getPublicKey(),
    )
    const publicKey = await parseCredentialPublicKey(cPublicKey, {
      uncompressed: true,
    })

    return {
      id: credential.id,
      publicKey,
      publicKeyCompressed: publicKey.slice(1),
    }
  } catch (error) {
    throw new Error('credential creation failed.', { cause: error })
  }
}
