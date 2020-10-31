export interface EncryptedData {
  data: string
  key: string
  iv: string
}

export interface ProtectedKeyBundle {
  privateKey: string
  publicKey: string
  salt: string
  iv: string
}
