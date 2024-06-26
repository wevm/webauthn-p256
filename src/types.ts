export type Hex = `0x${string}`

export type PublicKey = {
  x: bigint
  y: bigint
}

export type WebAuthnSignature = {
  authenticatorData: Hex
  challengeIndex: bigint
  clientDataJSON: string
  typeIndex: bigint
  r: bigint
  s: bigint
}

////////////////////////////////////////////////////////////////////////
// Utilities
////////////////////////////////////////////////////////////////////////

export type Prettify<T> = {
  [K in keyof T]: T[K]
} & {}

export type OneOf<
  union extends object,
  fallback extends object | undefined = undefined,
  ///
  keys extends KeyofUnion<union> = KeyofUnion<union>,
> = union extends infer Item
  ? Prettify<
      Item & {
        [_K in Exclude<keys, keyof Item>]?: fallback extends object
          ? // @ts-ignore
            fallback[_K]
          : undefined
      }
    >
  : never
type KeyofUnion<type> = type extends type ? keyof type : never
