import { useState } from 'react'
import { http, createPublicClient, stringify } from 'viem'
import { mainnet } from 'viem/chains'
import {
  type CreateCredentialReturnType,
  type Hex,
  type SignReturnType,
  createCredential,
  parsePublicKey,
  parseSignature,
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
  const [signResponse, setSignResponse] = useState<SignReturnType>()
  const [verified, setVerified] = useState<boolean>()

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
          <br />
          <strong>Public Key: </strong>
          <br />
          <pre>{stringify(parsePublicKey(credential.publicKey), null, 2)}</pre>
          <strong>Public Key (serialized): </strong>
          <br />
          <pre>{credential.publicKey}</pre>
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

            const response = await sign({
              hash: digest,
              credentialId: credential?.id,
            })
            setSignResponse(response)
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
        {signResponse && (
          <div>
            <strong>Signature:</strong>
            <br />
            <pre>{stringify(signResponse.signature, null, 2)}</pre>
            <br />
            <strong>Webauthn Data:</strong>
            <br />
            <pre>{stringify(signResponse.webauthn, null, 2)}</pre>
          </div>
        )}
        {signResponse && credential && (
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
                const signature = formData.get('signature') as Hex
                const {
                  authenticatorData,
                  challengeIndex,
                  clientDataJSON,
                  typeIndex,
                  userVerificationRequired,
                } = JSON.parse(formData.get('webauthn') as string)

                const webauthnData = {
                  authenticatorData,
                  challengeIndex,
                  clientDataJSON,
                  typeIndex,
                  userVerificationRequired,
                } as const

                const { x, y } = parsePublicKey(credential.publicKey)

                const verified = await (() => {
                  if (type === 'onchain')
                    return client.readContract({
                      abi: webauthn.abi,
                      code: webauthn.bytecode,
                      functionName: 'verify',
                      args: [
                        digest,
                        true,
                        { ...webauthnData, ...parseSignature(signature) },
                        x,
                        y,
                      ],
                    })
                  return verify({
                    hash: digest,
                    publicKey: credential.publicKey,
                    signature,
                    webauthn: webauthnData,
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
              <label>Webauthn Data</label>
              <div>
                <textarea name="webauthn" style={{ height: 100, width: 500 }} />
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
