import { useState } from 'react'
import { http, createPublicClient, stringify } from 'viem'
import { mainnet } from 'viem/chains'
import {
  type CreateCredentialReturnType,
  type Hex,
  createCredential,
  parsePublicKey,
  sign,
} from 'webauthn-p256'
import { daimoWebauthn, webauthn } from './contracts'

const client = createPublicClient({
  chain: mainnet,
  transport: http(),
})

export function App() {
  const [credential, setCredential] = useState<CreateCredentialReturnType>()
  const [signature, setSignature] = useState<any>()

  const publicKey = credential?.publicKey
    ? parsePublicKey(credential?.publicKey)
    : undefined

  return (
    <div>
      <h1>WebAuthn P256</h1>
      <hr />
      <h2>Create credential</h2>
      <div>
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            const formData = new FormData(e.target as HTMLFormElement)

            const credential_ = await createCredential({
              name: formData.get('name') as string,
            })
            setCredential(credential_)
          }}
        >
          <input defaultValue="Example" name="name" placeholder="Name" />
          <button type="submit">Create credential</button>
        </form>
      </div>
      <br />
      {credential && (
        <div>
          <strong>Credential ID:</strong>
          <br />
          {credential.id}
          <br />
          <strong>Public Key: </strong>
          <br />
          {credential.publicKeyCompressed}
          <br />
          <strong>x:</strong> {publicKey?.x.toString()}
          <br />
          <strong>y:</strong> {publicKey?.y.toString()}
        </div>
      )}
      <br />
      <hr />
      <h2>Sign digest</h2>
      <div>
        <form
          onSubmit={async (e) => {
            e.preventDefault()
            if (!publicKey) throw new Error('publicKey is required')
            const formData = new FormData(e.target as HTMLFormElement)
            const digest = formData.get('digest') as Hex

            const signature = await sign({
              digest,
              credentialId: credential?.id,
            })
            setSignature(signature)
            const result = await client.readContract({
              abi: webauthn.abi,
              code: webauthn.bytecode,
              functionName: 'verify',
              args: [digest, true, signature, publicKey.x, publicKey.y],
            })
            console.log(result)
          }}
        >
          <input
            defaultValue="0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf"
            name="digest"
            placeholder="Digest"
          />
          <button type="submit">Sign</button>
        </form>
        <br />
        {credential && (
          <div>
            <strong>Signature:</strong>
            <br />
            <pre>{stringify(signature, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  )
}
