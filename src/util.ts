import { ExportedProtectedKeyPair, ProtectedKeyPair } from './types'

// Required for Node.js support
let crypto: Crypto = globalThis.process?.versions?.node
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

export const deriveBitsFromPassword = async (
  password: string,
  salt: ArrayBuffer
): Promise<ArrayBuffer> => {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    stringToArrayBuffer(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt: salt,
      iterations: 100000
    },
    baseKey,
    256
  )

  return derivedBits
}

export const deriveKeyFromPassword = async (
  password: string,
  salt: ArrayBuffer
): Promise<CryptoKey> => {
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
      hash: 'SHA-256',
      salt: salt,
      iterations: 100000
    },
    baseKey,
    {
      name: 'AES-GCM',
      length: 256
    },
    false,
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
    publicKey: exportedPublicKey,
    privateKey: wrappedPrivateKey,
    iv: iv,
    salt: salt
  }
}

export const unlockProtectedKeyPair = async (
  protectedKeyPair: ProtectedKeyPair,
  password: string,
  type: 'RSA-OAEP' | 'RSA-PSS'
): Promise<CryptoKeyPair> => {
  const derivedKey = await deriveKeyFromPassword(
    password,
    protectedKeyPair.salt
  )
  const unwrappedPrivateKey = await crypto.subtle.unwrapKey(
    'pkcs8',
    protectedKeyPair.privateKey,
    derivedKey,
    {
      name: 'AES-GCM',
      iv: protectedKeyPair.iv
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
      protectedKeyPair.publicKey,
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

export const exportProtectedKeyPair = (
  protectedKeyPair: ProtectedKeyPair
): ExportedProtectedKeyPair => {
  return {
    privateKey: arrayBufferToArray(protectedKeyPair.privateKey),
    publicKey: arrayBufferToArray(protectedKeyPair.publicKey),
    salt: arrayBufferToArray(protectedKeyPair.salt),
    iv: arrayBufferToArray(protectedKeyPair.iv)
  }
}

export const importProtectedKeyPair = (
  exportedProtectedKeyPair: ExportedProtectedKeyPair
): ProtectedKeyPair => {
  return {
    privateKey: arrayToArrayBuffer(exportedProtectedKeyPair.privateKey),
    publicKey: arrayToArrayBuffer(exportedProtectedKeyPair.publicKey),
    salt: arrayToArrayBuffer(exportedProtectedKeyPair.salt),
    iv: arrayToArrayBuffer(exportedProtectedKeyPair.iv)
  }
}
