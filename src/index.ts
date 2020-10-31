import {
  stringToArrayBuffer,
  arrayBufferToString,
  deriveKeyFromPassword
} from './util'
import { EncryptedData, ProtectedKeyBundle } from './types'

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
    key: arrayBufferToString(wrappedKey),
    data: arrayBufferToString(encryptedData),
    iv: arrayBufferToString(iv)
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
    stringToArrayBuffer(data.key),
    privateKey,
    {
      name: 'RSA-OAEP'
    },
    {
      name: 'AES-GCM'
    },
    false,
    ['decrypt']
  )
  const iv = stringToArrayBuffer(data.iv)
  const decryptedData = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv
    },
    sessionKey,
    stringToArrayBuffer(data.data)
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
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['unwrapKey']
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
    'raw',
    keypair.privateKey,
    derivedKey,
    {
      name: 'AES-GCM',
      iv
    }
  )

  const exportedPublicKey = await crypto.subtle.exportKey(
    'raw',
    keypair.publicKey
  )

  return {
    privateKey: arrayBufferToString(wrappedPrivateKey),
    publicKey: arrayBufferToString(exportedPublicKey),
    salt: arrayBufferToString(salt),
    iv: arrayBufferToString(iv)
  }
}
/**
 * Unlocks a protected keybundle with a password and returns a {@link CryptoKeyPair}
 * @param password The password used to protect the keybundle
 * @param keyBundle The user's keybundle
 */
export const unlockProtectedKeyBundle = async (
  password: string,
  keyBundle: ProtectedKeyBundle
): Promise<CryptoKeyPair> => {
  const derivedKey = await deriveKeyFromPassword(
    password,
    stringToArrayBuffer(keyBundle.salt)
  )

  const unwrappedPrivateKey = await crypto.subtle.unwrapKey(
    'raw',
    stringToArrayBuffer(keyBundle.privateKey),
    derivedKey,
    {
      name: 'AES-GCM',
      iv: stringToArrayBuffer(keyBundle.iv)
    },
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    false,
    ['unwrapKey']
  )

  const keyPair = new CryptoKeyPair()
  keyPair.privateKey = unwrappedPrivateKey
  keyPair.publicKey = await crypto.subtle.importKey(
    'raw',
    stringToArrayBuffer(keyBundle.publicKey),
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['wrapKey']
  )

  return keyPair
}
/**
 * Imports another user's public key
 * @param publicKey
 */
export const importPublicKey = async (publicKey: string) => {
  return await crypto.subtle.importKey(
    'raw',
    stringToArrayBuffer(publicKey),
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['wrapKey']
  )
}
