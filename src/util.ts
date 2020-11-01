import { ProtectedKeyPair } from './types'

// Required for Node.js support
let crypto: Crypto = process?.versions?.node
  ? require('crypto').webcrypto
  : window.crypto

export const stringToArrayBuffer = (str: string) => {
  const encoder = new TextEncoder()
  return encoder.encode(str)
}

export const arrayBufferToString = (arrayBuffer: ArrayBuffer) => {
  const decoder = new TextDecoder()
  return decoder.decode(arrayBuffer)
}

export const arrayBufferToArray = (arrayBuffer: ArrayBuffer) => {
  return Array.from(new Uint8Array(arrayBuffer))
}

export const arrayToArrayBuffer = (array: number[]) => {
  return new Uint8Array(array).buffer
}

export const deriveKeyFromPassword = async (
  password: string,
  salt: ArrayBuffer
) => {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    stringToArrayBuffer(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  )

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['wrapKey', 'unwrapKey']
  )

  return derivedKey
}

export const createProtectedKeyPair = async (
  keyPair: CryptoKeyPair,
  password: string
): Promise<ProtectedKeyPair> => {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const derivedKey = await deriveKeyFromPassword(password, salt)

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const wrappedPrivateKey = await crypto.subtle.wrapKey(
    'pkcs8',
    keyPair.privateKey,
    derivedKey,
    {
      name: 'AES-GCM',
      iv
    }
  )
  const exportedPublicKey = await crypto.subtle.exportKey(
    'spki',
    keyPair.publicKey
  )

  return {
    publicKey: arrayBufferToArray(exportedPublicKey),
    privateKey: arrayBufferToArray(wrappedPrivateKey),
    iv: arrayBufferToArray(iv),
    salt: arrayBufferToArray(salt)
  }
}

export const unlockProtectedKeyPair = async (
  protectedKeyPair: ProtectedKeyPair,
  password: string,
  type: 'RSA-OAEP' | 'RSA-PSS'
): Promise<CryptoKeyPair> => {
  const derivedKey = await deriveKeyFromPassword(
    password,
    arrayToArrayBuffer(protectedKeyPair.salt)
  )

  const unwrappedPrivateKey = await crypto.subtle.unwrapKey(
    'pkcs8',
    arrayToArrayBuffer(protectedKeyPair.privateKey),
    derivedKey,
    {
      name: 'AES-GCM',
      iv: arrayToArrayBuffer(protectedKeyPair.iv)
    },
    {
      name: type,
      hash: 'SHA-256'
    },
    true,
    type === 'RSA-OAEP' ? ['unwrapKey'] : ['sign']
  )

  const keyPair: CryptoKeyPair = {
    privateKey: unwrappedPrivateKey,
    publicKey: await crypto.subtle.importKey(
      'spki',
      arrayToArrayBuffer(protectedKeyPair.publicKey),
      {
        name: type,
        hash: 'SHA-256'
      },
      true,
      type === 'RSA-OAEP' ? ['wrapKey'] : ['verify']
    )
  }

  return keyPair
}
