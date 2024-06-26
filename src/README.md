# webauthn-p256

P256 signature utilities for WebAuthn.

## Install

```bash
npm i webauthn-p256
```

```bash
pnpm add webauthn-p256
```

```bash
bun i webauthn-p256
```

## Usage

```ts
import { createCredential, sign, verify } from 'webauthn-p256'

const credential = createCredential({
  name: 'Example',
})

const signature = await sign({
  credentialId: credential.id,
  hash: '0x...'
})

const verified = await verify({
  signature,
  publicKey: credential.publicKey,
})
```

### Onchain Verification

We can also verify WebAuthn signatures onchain via contracts that expose a WebAuthn verifier interface.

The example below uses [Viem](https://viem.sh) to call the `verify` function on the [`WebAuthn.sol` contract](https://github.com/base-org/webauthn-sol/blob/main/src/WebAuthn.sol#L105). However, in a real world scenario, a contract implementing the WebAuthn verifier interface will call the `verify` function (e.g. a `isValidSignature` interface on an ERC-4337 Smart Wallet).

```ts
import { createCredential, parsePublicKey, sign } from 'webauthn-p256'
import { createPublicClient, http } from 'viem'
import { mainnet } from 'viem/chains'

const abi = parseAbi([
  'struct WebAuthnAuth { bytes authenticatorData; string clientDataJSON; uint256 challengeIndex; uint256 typeIndex; uint256 r; uint256 s; }',
  'function verify(bytes, bool, WebAuthnAuth, uint256, uint256)'
])
const bytecode = '0x...'

const credential = createCredential({
  name: 'Example',
})

const hash = '0x...'

const signature = await sign({
  credentialId: credential.id,
  hash
})

const { x, y } = parsePublicKey(credential.publicKey)

const verified = await client.readContract({
  abi,
  code,
  functionName: 'verify',
  args: [hash, true, signature, publicKey.x, publicKey.y],
})
```

## Authors

- [@jxom](https://github.com/jxom) (jxom.eth, [X](https://x.com/jakemoxey))

## License

[MIT](/LICENSE) License