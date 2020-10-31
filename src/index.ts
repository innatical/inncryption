import {
  stringToArrayBuffer,
  arrayBufferToString,
  arrayBufferToArray,
  arrayToArrayBuffer,
  deriveKeyFromPassword
} from './util'
import { EncryptedData, ProtectedKeyBundle } from './types'

// Required for Node.js support
let crypto = process?.versions?.node
  ? require('crypto').webcrypto
  : window.crypto

export { EncryptedData, ProtectedKeyBundle }

/**
 * Encrypts data for a recipient
 * @param data The data to encrypt
 * @param publicKey The recipient's public key
 */
export const encryptData = async (
  data: string,
  publicKey: CryptoKey
): Promise<EncryptedData> => {
  const sessionKey = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['encrypt']
  )

  const wrappedKey = await crypto.subtle.wrapKey('raw', sessionKey, publicKey, {
    name: 'RSA-OAEP'
  })

  const iv = crypto.getRandomValues(new Uint8Array(12))

  const encryptedData = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    sessionKey,
    stringToArrayBuffer(data)
  )

  return {
    key: arrayBufferToArray(wrappedKey),
    data: arrayBufferToArray(encryptedData),
    iv: arrayBufferToArray(iv)
  }
}

/**
 * Decrypts data from a sender
 * @param data The EncryptedData object to decrypt
 * @param privateKey Your private key
 * @return The unencrypted data
 */
export const decryptData = async (
  data: EncryptedData,
  privateKey: CryptoKey
) => {
  const sessionKey = await crypto.subtle.unwrapKey(
    'raw',
    arrayToArrayBuffer(data.key),
    privateKey,
    {
      name: 'RSA-OAEP'
    },
    {
      name: 'AES-GCM'
    },
    true,
    ['decrypt']
  )
  const iv = arrayToArrayBuffer(data.iv)
  const decryptedData = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv
    },
    sessionKey,
    arrayToArrayBuffer(data.data)
  )

  return arrayBufferToString(decryptedData)
}
/**
 * Generates a RSA-OAEP keypair for unwrapping session keys
 */
export const generateMasterKeypair = async () => {
  return await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['unwrapKey', 'wrapKey']
  )
}

/**
 * Creates a protected keybundle to upload to a keyserver
 * @param keypair The user's master keypair
 * @param password The password to protect the keypair with
 */
export const createProtectedKeyBundle = async (
  keypair: CryptoKeyPair,
  password: string
): Promise<ProtectedKeyBundle> => {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const derivedKey = await deriveKeyFromPassword(password, salt)

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const wrappedPrivateKey = await crypto.subtle.wrapKey(
    'pkcs8',
    keypair.privateKey,
    derivedKey,
    {
      name: 'AES-GCM',
      iv
    }
  )
  const exportedPublicKey = await crypto.subtle.exportKey(
    'spki',
    keypair.publicKey
  )

  return {
    privateKey: arrayBufferToArray(wrappedPrivateKey),
    publicKey: arrayBufferToArray(exportedPublicKey),
    salt: arrayBufferToArray(salt),
    iv: arrayBufferToArray(iv)
  }
}
/**
 * Unlocks a protected keybundle with a password and returns a {@link CryptoKeyPair}
 * @param keyBundle The user's keybundle
 * @param password The password used to protect the keybundle
 */
export const unlockProtectedKeyBundle = async (
  keyBundle: ProtectedKeyBundle,
  password: string
): Promise<CryptoKeyPair> => {
  const derivedKey = await deriveKeyFromPassword(
    password,
    arrayToArrayBuffer(keyBundle.salt)
  )

  const unwrappedPrivateKey = await crypto.subtle.unwrapKey(
    'pkcs8',
    arrayToArrayBuffer(keyBundle.privateKey),
    derivedKey,
    {
      name: 'AES-GCM',
      iv: arrayToArrayBuffer(keyBundle.iv)
    },
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['unwrapKey']
  )

  const keyPair: CryptoKeyPair = {
    privateKey: unwrappedPrivateKey,
    publicKey: await crypto.subtle.importKey(
      'spki',
      arrayToArrayBuffer(keyBundle.publicKey),
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      true,
      ['wrapKey']
    )
  }

  return keyPair
}
/**
 * Imports another user's public key
 * @param publicKey
 */
export const importPublicKey = async (publicKey: number[]) => {
  return await crypto.subtle.importKey(
    'spki',
    arrayToArrayBuffer(publicKey),
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['wrapKey']
  )
}
