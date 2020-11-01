import * as inncrypt from '.'

test('signs and verifies', async () => {
  const message =
    'Octii is a chat service by Innatical, focusing on simplicity, privacy, and extensibility.'
  const keychain = await inncrypt.generateKeychain()

  const signedMessage = await inncrypt.signMessage(keychain, message)

  expect(
    await inncrypt.verifyMessage(
      signedMessage,
      keychain.signingKeyPair.publicKey
    )
  ).toStrictEqual({
    verified: true,
    message
  })
}, 10000)

test('protects and unlocks keychains', async () => {
  // Required for Node.js support
  const crypto: Crypto = process?.versions?.node
    ? require('crypto').webcrypto
    : window.crypto

  const keychain = await inncrypt.generateKeychain()
  const password = 'password'

  const protectedKeychain = await inncrypt.createProtectedKeychain(
    keychain,
    password
  )
  const unlockedKeychain = await inncrypt.unlockProtectedKeychain(
    protectedKeychain,
    password
  )
  expect([
    await crypto.subtle.exportKey(
      'spki',
      unlockedKeychain.encryptionKeyPair.publicKey
    ),
    await crypto.subtle.exportKey(
      'pkcs8',
      unlockedKeychain.encryptionKeyPair.privateKey
    ),
    await crypto.subtle.exportKey(
      'spki',
      unlockedKeychain.signingKeyPair.publicKey
    ),
    await crypto.subtle.exportKey(
      'pkcs8',
      unlockedKeychain.signingKeyPair.privateKey
    )
  ]).toStrictEqual([
    await crypto.subtle.exportKey('spki', keychain.encryptionKeyPair.publicKey),
    await crypto.subtle.exportKey(
      'pkcs8',
      keychain.encryptionKeyPair.privateKey
    ),
    await crypto.subtle.exportKey('spki', keychain.signingKeyPair.publicKey),
    await crypto.subtle.exportKey('pkcs8', keychain.signingKeyPair.privateKey)
  ])
}, 10000)

test('encrypts and decrypts', async () => {
  const message =
    'Octii is a chat service by Innatical, focusing on simplicity, privacy, and extensibility.'
  const sender = await inncrypt.generateKeychain()
  const recipient = await inncrypt.generateKeychain()

  const encryptedMessage = await inncrypt.encryptMessage(
    sender,
    recipient.encryptionKeyPair.publicKey,
    message
  )
  const decryptedMessage = await inncrypt.decryptMessage(
    recipient,
    sender.signingKeyPair.publicKey,
    encryptedMessage
  )

  expect(decryptedMessage).toStrictEqual({
    verified: true,
    message
  })
}, 10000)
