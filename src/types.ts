export interface SignedMessage {
  data: ArrayBuffer
  signature: ArrayBuffer
}

export interface ExportedSignedMessage {
  data: number[]
  signature: number[]
}
export interface EncryptedMessage extends SignedMessage {
  key: ArrayBuffer
  iv: ArrayBuffer
}

export interface ExportedEncryptedMessage extends ExportedSignedMessage {
  key: number[]
  iv: number[]
}

export interface Keychain {
  encryptionKeyPair: CryptoKeyPair
  signingKeyPair: CryptoKeyPair
  authenticationToken: string
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
  tokenSalt: Uint8Array
}

export interface VerifiedMessage {
  verified: boolean
  message: string
}

export interface ExportedProtectedKeyPair {
  privateKey: number[]
  publicKey: number[]
  salt: number[]
  iv: number[]
}

export interface ExportedProtectedKeychain {
  encryption: ExportedProtectedKeyPair
  signing: ExportedProtectedKeyPair
  tokenSalt: number[]
}
