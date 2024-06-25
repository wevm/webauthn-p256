import { hexToBytes } from '@noble/hashes/utils'
import { describe, expect, test } from 'vitest'
import { parseCredentialPublicKey, parsePublicKey } from './publicKey.js'

describe('parseCredentialPublicKey', () => {
  test('default', async () => {
    const cPublicKey = hexToBytes(
      '3059301306072a8648ce3d020106082a8648ce3d030107034200041fd0593f9f25ed8ecab174bba6ea6fcf22909c53b3a4e34d5a9f6abd37d6f98cf4954eec64a4b8a39c89e7c4a00b315359e0113fa3fa325ac23cc30ab98a5f21',
    )
    const publicKey = await parseCredentialPublicKey(cPublicKey)
    expect(publicKey).toMatchInlineSnapshot(
      `"0x041fd0593f9f25ed8ecab174bba6ea6fcf22909c53b3a4e34d5a9f6abd37d6f98cf4954eec64a4b8a39c89e7c4a00b315359e0113fa3fa325ac23cc30ab98a5f21"`,
    )
  })

  test('args: compressed', async () => {
    const cPublicKey = hexToBytes(
      '3059301306072a8648ce3d020106082a8648ce3d030107034200042caa86454963544bbc964f29979ddb953395f1baa9b123b1edb6ed1109bf0cb2ce91893a28a0f9f0c6b85edf44b01e95d46a39eeeab45a0b2583c05cb6414904',
    )
    const publicKey = await parseCredentialPublicKey(cPublicKey, {
      compressed: true,
    })
    expect(publicKey).toMatchInlineSnapshot(
      `"0x2caa86454963544bbc964f29979ddb953395f1baa9b123b1edb6ed1109bf0cb2ce91893a28a0f9f0c6b85edf44b01e95d46a39eeeab45a0b2583c05cb6414904"`,
    )
  })
})

describe('parsePublicKey', () => {
  test('default', () => {
    const publicKey = hexToBytes(
      '2caa86454963544bbc964f29979ddb953395f1baa9b123b1edb6ed1109bf0cb2ce91893a28a0f9f0c6b85edf44b01e95d46a39eeeab45a0b2583c05cb6414904',
    )
    const parsed = parsePublicKey(publicKey)
    expect(parsed).toMatchInlineSnapshot(`
      {
        "x": 20203056040651495381197951451296140612901279933246014793928478310014916693170n,
        "y": 93433586739750872222655519548076692627611806436511880340534198806289473161476n,
      }
    `)
  })

  test('uncompressed', () => {
    const publicKey = hexToBytes(
      '042caa86454963544bbc964f29979ddb953395f1baa9b123b1edb6ed1109bf0cb2ce91893a28a0f9f0c6b85edf44b01e95d46a39eeeab45a0b2583c05cb6414904',
    )
    const parsed = parsePublicKey(publicKey)
    expect(parsed).toMatchInlineSnapshot(`
      {
        "x": 20203056040651495381197951451296140612901279933246014793928478310014916693170n,
        "y": 93433586739750872222655519548076692627611806436511880340534198806289473161476n,
      }
    `)
  })
})
