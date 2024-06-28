import { describe, expect, test } from 'vitest'
import { verify } from './verify.js'

describe('verify', () => {
  test('default', () => {
    const publicKey = {
      prefix: 4,
      x: 15325272481743543470187210372131079389379804084126119117911265853867256769440n,
      y: 74947999673872536163854436677160946007685903587557427331495653571111132132212n,
    }
    const signature = {
      authenticatorData:
        '0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000',
      challengeIndex: 23n,
      clientDataJSON:
        '{"type":"webauthn.get","challenge":"9jEFijuhEWrM4SOW-tChJbUEHEP44VcjcJ-Bqo1fTM8","origin":"http://localhost:5173","crossOrigin":false}',
      r: 10330677067519063752777069525326520293658884904426299601620960859195372963151n,
      s: 47017859265388077754498411591757867926785106410894171160067329762716841868244n,
      typeIndex: 1n,
    } as const

    expect(verify({ publicKey, signature })).toBeTruthy()
  })

  test('default', () => {
    const publicKey = {
      prefix: 4,
      x: 15325272481743543470187210372131079389379804084126119117911265853867256769440n,
      y: 74947999673872536163854436677160946007685903587557427331495653571111132132212n,
    }
    const signature = {
      authenticatorData:
        '0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000',
      challengeIndex: 23n,
      clientDataJSON:
        '{"type":"webauthn.get","challenge":"9jEFijuhEWrM4SOW-tChJbUEHEP44VcjcJ-Bqo1fTM8","origin":"http://localhost:5173","crossOrigin":false,"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}',
      r: 92217130139243395344713469331864871617892993489147165241879962954542036045090n,
      s: 25785067610647358687769954197992440351568013796562547723755309225289815468181n,
      typeIndex: 1n,
    } as const

    expect(verify({ publicKey, signature })).toBeTruthy()
  })
})
