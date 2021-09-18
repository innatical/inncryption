import * as inncrypt from '.'
import {
  arrayBufferToBase64,
  arrayBufferToString,
  arrayToArrayBuffer,
  stringToArrayBuffer
} from './util'

test('signs and verifies', async () => {
  const message =
    'Octii is a chat service by Innatical, focusing on simplicity, privacy, and extensibility.'
  const password = 'password'
  const keychain = await inncrypt.generateKeychain(password)

  const signedMessage = await inncrypt.signMessage(keychain, message)

  expect(
    await inncrypt.verifyMessage(
      signedMessage,
      keychain.signingKeyPair.publicKey!
    )
  ).toStrictEqual({
    verified: true,
    message
  })
}, 10000)

test('protects and unlocks keychains', async () => {
  // Required for Node.js support
  let crypto: Crypto = !globalThis?.crypto?.subtle
    ? require('crypto').webcrypto
    : globalThis.crypto

  const password = 'password'
  const keychain = await inncrypt.generateKeychain(password)

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
      unlockedKeychain.encryptionKeyPair.publicKey!
    ),
    await crypto.subtle.exportKey(
      'pkcs8',
      unlockedKeychain.encryptionKeyPair.privateKey!
    ),
    await crypto.subtle.exportKey(
      'spki',
      unlockedKeychain.signingKeyPair.publicKey!
    ),
    await crypto.subtle.exportKey(
      'pkcs8',
      unlockedKeychain.signingKeyPair.privateKey!
    ),
    unlockedKeychain.authenticationToken
  ]).toStrictEqual([
    await crypto.subtle.exportKey(
      'spki',
      keychain.encryptionKeyPair.publicKey!
    ),
    await crypto.subtle.exportKey(
      'pkcs8',
      keychain.encryptionKeyPair.privateKey!
    ),
    await crypto.subtle.exportKey('spki', keychain.signingKeyPair.publicKey!),
    await crypto.subtle.exportKey('pkcs8', keychain.signingKeyPair.privateKey!),
    keychain.authenticationToken
  ])
}, 10000)

test('encrypts and decrypts', async () => {
  const message =
    'Octii is a chat service by Innatical, focusing on simplicity, privacy, and extensibility.'
  const password = 'password'
  const sender = await inncrypt.generateKeychain(password)
  const recipient = await inncrypt.generateKeychain(password)

  const encryptedMessage = await inncrypt.encryptMessage(
    sender,
    recipient.encryptionKeyPair.publicKey!,
    message
  )
  const decryptedMessage = await inncrypt.decryptMessage(
    recipient,
    sender.signingKeyPair.publicKey!,
    encryptedMessage
  )

  expect(decryptedMessage).toStrictEqual({
    verified: true,
    message
  })
}, 10000)

test('generates authenticationToken', async () => {
  // Required for Node.js support
  let crypto: Crypto = !globalThis?.crypto?.subtle
    ? require('crypto').webcrypto
    : globalThis.crypto

  const password = 'password'
  const keychain = await inncrypt.generateKeychain(password)
  const baseKey = await crypto.subtle.importKey(
    'raw',
    stringToArrayBuffer(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )
  expect(keychain.authenticationToken).toStrictEqual(
    arrayBufferToBase64(
      await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          hash: 'SHA-256',
          salt: keychain.tokenSalt,
          iterations: 100000
        },
        baseKey,
        256
      )
    )
  )
})

test('exports and imports', async () => {
  const password = 'password'
  const keychain = await inncrypt.generateKeychain(password)

  const protectedKeychain = await inncrypt.createProtectedKeychain(
    keychain,
    password
  )

  const exportedProtectedKeychain =
    inncrypt.exportProtectedKeychain(protectedKeychain)

  const importedProtectedKeychain = inncrypt.importProtectedKeychain(
    exportedProtectedKeychain
  )

  expect([
    arrayToArrayBuffer(exportedProtectedKeychain.encryption.publicKey),
    arrayToArrayBuffer(exportedProtectedKeychain.encryption.privateKey),
    arrayToArrayBuffer(exportedProtectedKeychain.encryption.salt),
    arrayToArrayBuffer(exportedProtectedKeychain.encryption.iv),
    arrayToArrayBuffer(exportedProtectedKeychain.signing.publicKey),
    arrayToArrayBuffer(exportedProtectedKeychain.signing.privateKey),
    arrayToArrayBuffer(exportedProtectedKeychain.signing.salt),
    arrayToArrayBuffer(exportedProtectedKeychain.signing.iv),
    new Uint8Array(exportedProtectedKeychain.tokenSalt)
  ]).toStrictEqual([
    importedProtectedKeychain.encryption.publicKey,
    importedProtectedKeychain.encryption.privateKey,
    importedProtectedKeychain.encryption.salt,
    importedProtectedKeychain.encryption.iv,
    importedProtectedKeychain.signing.publicKey,
    importedProtectedKeychain.signing.privateKey,
    importedProtectedKeychain.signing.salt,
    importedProtectedKeychain.signing.iv,
    importedProtectedKeychain.tokenSalt
  ])
})
