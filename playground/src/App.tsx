import { useState } from 'react'
import { http, createPublicClient, stringify } from 'viem'
import { mainnet } from 'viem/chains'
import {
  type CreateCredentialReturnType,
  type Hex,
  type WebAuthnSignature,
  createCredential,
  parsePublicKey,
  sign,
  verify,
} from 'webauthn-p256'
import { webauthn } from './contracts'

const client = createPublicClient({
  chain: mainnet,
  transport: http(),
})

export function App() {
  const [credential, setCredential] = useState<CreateCredentialReturnType>()
  const [signature, setSignature] = useState<WebAuthnSignature>()
  const [verified, setVerified] = useState<boolean>()

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
            const formData = new FormData(e.target as HTMLFormElement)
            const digest = formData.get('digest') as Hex

            const signature = await sign({
              digest,
              credentialId: credential?.id,
            })
            setSignature(signature)
          }}
        >
          <input
            defaultValue="0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf"
            name="digest"
            placeholder="Digest"
            style={{ width: 500 }}
          />
          <button type="submit">Sign</button>
        </form>
        <br />
        {signature && (
          <div>
            <strong>Signature:</strong>
            <br />
            <pre>{stringify(signature, null, 2)}</pre>
          </div>
        )}
        {signature && credential && publicKey && (
          <div>
            <br />
            <hr />
            <h2>Verify signature</h2>
            <form
              onSubmit={async (e) => {
                e.preventDefault()

                setVerified(undefined)

                const formData = new FormData(e.target as HTMLFormElement)
                const digest = formData.get('digest') as Hex
                const type = formData.get('type') as string
                const {
                  authenticatorData,
                  challengeIndex,
                  clientDataJSON,
                  r,
                  s,
                  typeIndex,
                } = JSON.parse(formData.get('signature') as string)

                const signature = {
                  authenticatorData,
                  challengeIndex: BigInt(challengeIndex),
                  clientDataJSON,
                  r: BigInt(r),
                  s: BigInt(s),
                  typeIndex: BigInt(typeIndex),
                } satisfies WebAuthnSignature

                const verified = await (() => {
                  if (type === 'onchain')
                    return client.readContract({
                      abi: webauthn.abi,
                      code: webauthn.bytecode,
                      functionName: 'verify',
                      args: [digest, true, signature, publicKey.x, publicKey.y],
                    })
                  return verify({
                    publicKey: credential.publicKey,
                    signature,
                  })
                })()

                setVerified(verified)
              }}
            >
              <label>Digest</label>
              <div>
                <input
                  defaultValue="0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf"
                  name="digest"
                  placeholder="Digest"
                  style={{ width: 500 }}
                />
              </div>
              <br />
              <label>Signature</label>
              <div>
                <textarea
                  name="signature"
                  style={{ height: 100, width: 500 }}
                />
              </div>
              <br />
              <div>
                <button name="type" value="offchain" type="submit">
                  Verify offchain
                </button>
                <button name="type" value="onchain" type="submit">
                  Verify onchain
                </button>
              </div>
              <br />
              {verified === true && <div>we gucci</div>}
              {verified === false && <div>we not gucci</div>}
            </form>
          </div>
        )}
      </div>
    </div>
  )
}
