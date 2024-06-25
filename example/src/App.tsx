import { createCredential } from 'webauthn-p256'

export function App() {
  return (
    <div>
      <h1>WebAuthn P256</h1>
      <button
        onClick={() => createCredential({ user: { name: 'foo' } })}
        type="button"
      >
        Create credential
      </button>
    </div>
  )
}
