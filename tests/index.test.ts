import {
  EncryptionPair,
  Keychain,
  SigningPair,
  SymmetricKey
} from '../src/index'

let key: SymmetricKey
let signing: SigningPair
let encryption: EncryptionPair
let keychain: Keychain

beforeAll(async () => {
  key = await SymmetricKey.generate()
  signing = await SigningPair.generate()
  encryption = await EncryptionPair.generate()
  keychain = await Keychain.generate()
})

describe('SymmetricKey', () => {
  it('can encrypt and decrypt data', async () => {
    const encrypted = await key.encrypt('owo')
    const decrypted = await key.decrypt(encrypted)
    expect(decrypted).toEqual('owo')
  })

  it('can export and import JWKs', async () => {
    const jwk = await key.toJWK()
    const key2 = await SymmetricKey.fromJWK(jwk)

    expect(key2).toEqual(key)
  })

  it('can generate keys from passwords', async () => {
    const salt = SymmetricKey.generateSalt()
    const key3 = await SymmetricKey.generateFromPassword('Some Password', salt)
    const key4 = await SymmetricKey.generateFromPassword('Some Password', salt)

    expect(key3).toEqual(key4)
  })
})

describe('SigningPair', () => {
  it('can sign and verify data', async () => {
    const signed = await signing.sign('owo')
    const unwrapped = await SigningPair.verify(
      signed,
      (
        await signing.toJWKPair()
      ).publicKey
    )

    if (unwrapped.ok !== true) throw new Error('Could not verify message')
    expect(unwrapped.message).toEqual('owo')
  })

  it('can export and import JWKPairs', async () => {
    const jwk = await signing.toJWKPair()
    const singing2 = await SigningPair.fromJWKPair(jwk)

    expect(signing).toEqual(singing2)
  })
})

describe('EncryptionPair', () => {
  it('can generate session key', async () => {
    const otherEncryption = await EncryptionPair.generate()
    const session1 = encryption.sessionKey(
      (await otherEncryption.toJWKPair()).publicKey
    )
    const session2 = otherEncryption.sessionKey(
      (await encryption.toJWKPair()).publicKey
    )

    expect(session1).toEqual(session2)
  })

  it('can export and import JWKPairs', async () => {
    const jwk = await encryption.toJWKPair()
    const encryption2 = await EncryptionPair.fromJWKPair(jwk)

    expect(encryption).toEqual(encryption2)
  })
})

describe('Keychain', () => {
  it('can export and import JWKKeychains', async () => {
    const jwk = await keychain.toJWKChain()
    const chain = await Keychain.fromJWKChain(jwk)

    expect(keychain).toEqual(chain)
  })
})
