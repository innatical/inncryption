export interface EncryptedData {
  data: string
  key: string
  iv: string
}

const stringToArrayBuffer = (str: string) => {
  const encoder = new TextEncoder()
  return encoder.encode(str)
}

const arrayBufferToString = (arrayBuffer: ArrayBuffer) => {
  const decoder = new TextDecoder()
  return decoder.decode(arrayBuffer)
}

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
