import {
  stringToArrayBuffer,
  arrayBufferToString,
  arrayToArrayBuffer,
  createProtectedKeyPair,
  unlockProtectedKeyPair,
  deriveBitsFromPassword
} from './util'
import {
  EncryptedMessage,
  Keychain,
  ProtectedKeychain,
  SignedMessage,
  VerifiedMessage
} from './types'

// Required for Node.js support
let crypto: Crypto = process?.versions?.node
  ? require('crypto').webcrypto
  : window.crypto

export { EncryptedMessage, ProtectedKeychain }

/**
 * Encrypts and signs a message
 * @param keychain The sender's keychain
 * @param publicEncryptionKey The recipient's public encryption key
 * @param message The message to encrypt
 * @returns The encrypted and signed message
 */
export const encryptMessage = async (
  keychain: Keychain,
  publicEncryptionKey: CryptoKey,
  message: string
): Promise<EncryptedMessage> => {
  const sessionKey = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256
    },
    true,
    ['encrypt']
  )

  const wrappedKey = await crypto.subtle.wrapKey(
    'raw',
    sessionKey,
    publicEncryptionKey,
    {
      name: 'RSA-OAEP'
    }
  )

  const iv = crypto.getRandomValues(new Uint8Array(12))

  const encryptedData = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    sessionKey,
    stringToArrayBuffer(message)
  )

  return {
    key: wrappedKey,
    data: encryptedData,
    iv: iv,
    signature: (await signMessage(keychain, message)).signature
  }
}

/**
 * Decrypts and verifies the signature of a message
 * @param keychain The recipient's keychain
 * @param publicSigningKey The sender's public signing key
 * @return The unencrypted and verified message
 */
export const decryptMessage = async (
  keychain: Keychain,
  publicSigningKey: CryptoKey,
  data: EncryptedMessage
): Promise<VerifiedMessage> => {
  const sessionKey = await crypto.subtle.unwrapKey(
    'raw',
    data.key,
    keychain.encryptionKeyPair.privateKey,
    {
      name: 'RSA-OAEP'
    },
    {
      name: 'AES-GCM'
    },
    true,
    ['decrypt']
  )
  const iv = data.iv
  const decryptedData = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv
    },
    sessionKey,
    data.data
  )
  const message = arrayBufferToString(decryptedData)

  return {
    message,
    verified: (
      await verifyMessage(
        {
          signature: data.signature,
          data: decryptedData
        },
        publicSigningKey
      )
    ).verified
  }
}

export const signMessage = async (
  keychain: Keychain,
  message: string
): Promise<SignedMessage> => {
  const signature = await crypto.subtle.sign(
    {
      name: 'RSA-PSS',
      saltLength: 32
    },
    keychain.signingKeyPair.privateKey,
    stringToArrayBuffer(message)
  )

  return {
    data: stringToArrayBuffer(message),
    signature: signature
  }
}

export const verifyMessage = async (
  message: SignedMessage,
  publicKey: CryptoKey
): Promise<VerifiedMessage> => {
  const verified = await crypto.subtle.verify(
    {
      name: 'RSA-PSS',
      saltLength: 32
    },
    publicKey,
    message.signature,
    message.data
  )
  return {
    verified,
    message: arrayBufferToString(message.data)
  }
}
/**
 * Generates a new {@link Keychain} used for encrypting session keys and signing
 * @param password The password to generate the {@link authenticationToken} with
 */
export const generateKeychain = async (password: string): Promise<Keychain> => {
  const encryptionKeyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['unwrapKey', 'wrapKey']
  )

  const signingKeyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  )

  const tokenSalt = crypto.getRandomValues(new Uint8Array(16))
  const authenticationToken = await deriveBitsFromPassword(password, tokenSalt)

  return {
    encryptionKeyPair,
    signingKeyPair,
    authenticationToken,
    tokenSalt
  }
}

/**
 * Creates a protected keychain to upload to a keyserver
 * @param keychain The user's keychain
 * @param password The password to protect the keychain with
 */
export const createProtectedKeychain = async (
  keychain: Keychain,
  password: string
): Promise<ProtectedKeychain> => {
  return {
    encryption: await createProtectedKeyPair(
      keychain.encryptionKeyPair,
      password
    ),
    signing: await createProtectedKeyPair(keychain.signingKeyPair, password),
    authenticationToken: keychain.authenticationToken,
    tokenSalt: keychain.tokenSalt
  }
}
/**
 * Unlocks a protected keychain with the user's password
 * @param protectedKeychain The user's protected keychain
 * @param password The password used to protect the keychain
 */
export const unlockProtectedKeychain = async (
  protectedKeychain: ProtectedKeychain,
  password: string
): Promise<Keychain> => {
  return {
    encryptionKeyPair: await unlockProtectedKeyPair(
      protectedKeychain.encryption,
      password,
      'RSA-OAEP'
    ),
    signingKeyPair: await unlockProtectedKeyPair(
      protectedKeychain.signing,
      password,
      'RSA-PSS'
    ),
    authenticationToken: protectedKeychain.authenticationToken,
    tokenSalt: protectedKeychain.tokenSalt
  }
}

/**
 * Imports another user's public key
 * @param publicKey The other user's public key
 * @param type The type of public key
 */
export const importPublicKey = async (
  publicKey: number[],
  type: 'encryption' | 'signing'
) => {
  return await crypto.subtle.importKey(
    'spki',
    arrayToArrayBuffer(publicKey),
    {
      name: type === 'encryption' ? 'RSA-OAEP' : 'RSA-PSS',
      hash: 'SHA-256'
    },
    true,
    type === 'encryption' ? ['wrapKey'] : ['verify']
  )
}
