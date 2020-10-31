export interface EncryptedData {
  data: number[]
  key: number[]
  iv: number[]
}

export interface ProtectedKeyBundle {
  privateKey: number[]
  publicKey: number[]
  salt: number[]
  iv: number[]
}
