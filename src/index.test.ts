import * as inncrypt from '.'

test('encrypts and decrypts', async () => {
  const message =
    'Octii is a chat service by Innatical, focusing on simplicity, privacy, and extensibility.'
  const recipient = await inncrypt.generateMasterKeypair()

  const encryptedMessage = await inncrypt.encryptData(
    message,
    recipient.publicKey
  )
  const decryptedMessage = await inncrypt.decryptData(
    encryptedMessage,
    recipient.privateKey
  )

  expect(decryptedMessage).toStrictEqual(message)
})

test('protects and unlocks keybundles', async () => {
  let crypto = process?.versions?.node
    ? require('crypto').webcrypto
    : window.crypto
  const password = 'password'
  const keypair = await inncrypt.generateMasterKeypair()

  const protectedBundle = await inncrypt.createProtectedKeyBundle(
    keypair,
    password
  )
  const unlockedBundle = await inncrypt.unlockProtectedKeyBundle(
    protectedBundle,
    password
  )

  expect([
    await crypto.subtle.exportKey('spki', unlockedBundle.publicKey),
    await crypto.subtle.exportKey('pkcs8', unlockedBundle.privateKey)
  ]).toStrictEqual([
    await crypto.subtle.exportKey('spki', keypair.publicKey),
    await crypto.subtle.exportKey('pkcs8', keypair.privateKey)
  ])
})
