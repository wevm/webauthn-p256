import { useState } from 'react'
import {
  type CreateCredentialReturnType,
  createCredential,
} from 'webauthn-p256'

export function App() {
  const [credential, setCredential] = useState<CreateCredentialReturnType>()

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
              excludeCredentialIds: credential ? [credential.id] : undefined,
              name: formData.get('name') as string,
            })
            console.log(credential_)
            setCredential(credential_)
          }}
        >
          <input name="name" placeholder="Name" />
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
          {/* <br />
          <strong>x:</strong> {coordinates?.x.toString()}
          <br />
          <strong>y:</strong> {coordinates?.y.toString()} */}
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
            const credential_ = await createCredential({
              excludeCredentialIds: credential ? [credential.id] : undefined,
              name: formData.get('name') as string,
            })
            setCredential(credential_)
          }}
        >
          <input name="hash" placeholder="Hash" />
          <button type="submit">Sign</button>
        </form>
      </div>
    </div>
  )
}
