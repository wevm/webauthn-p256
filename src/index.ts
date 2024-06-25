export {
  type CreateCredentialParameters,
  type CreateCredentialReturnType,
  createCredential,
} from './credential/createCredential.js'
export {
  type GetCredentialCreationOptionsParameters,
  type GetCredentialCreationOptionsReturnType,
  getCredentialCreationOptions,
} from './credential/getCredentialCreationOptions.js'

export type { Hex } from './types.js'

export {
  base64ToBase64Url,
  base64ToUtf8,
  base64UrlToBase64,
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToCryptoKey,
  bytesToHex,
  cryptoKeyToBytes,
  hexToBytes,
  utf8ToBase64,
} from './utils/conversion.js'
export {
  type ParseCredentialPublicKeyOptions,
  parseCredentialPublicKey,
} from './utils/publicKey.js'
