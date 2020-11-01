export interface SignedMessage {
  data: number[]
  signature: number[]
}

export interface EncryptedMessage extends SignedMessage {
  key: number[]
  iv: number[]
}

export interface Keychain {
  encryptionKeyPair: CryptoKeyPair
  signingKeyPair: CryptoKeyPair
}

export interface ProtectedKeyPair {
  privateKey: number[]
  publicKey: number[]
  salt: number[]
  iv: number[]
}

export interface ProtectedKeychain {
  encryption: ProtectedKeyPair
  signing: ProtectedKeyPair
}

export interface VerifiedMessage {
  verified: boolean
  message: string
}
