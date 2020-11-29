export interface SignedMessage {
  data: ArrayBuffer
  signature: ArrayBuffer
}

export interface EncryptedMessage extends SignedMessage {
  key: ArrayBuffer
  iv: ArrayBuffer
}

export interface Keychain {
  encryptionKeyPair: CryptoKeyPair
  signingKeyPair: CryptoKeyPair
  authenticationToken: ArrayBuffer
  tokenSalt: Uint8Array
}

export interface ProtectedKeyPair {
  privateKey: ArrayBuffer
  publicKey: ArrayBuffer
  salt: ArrayBuffer
  iv: ArrayBuffer
}

export interface ProtectedKeychain {
  encryption: ProtectedKeyPair
  signing: ProtectedKeyPair
}

export interface VerifiedMessage {
  verified: boolean
  message: string
}
