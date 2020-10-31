export const stringToArrayBuffer = (str: string) => {
  const encoder = new TextEncoder()
  return encoder.encode(str)
}

export const arrayBufferToString = (arrayBuffer: ArrayBuffer) => {
  const decoder = new TextDecoder()
  return decoder.decode(arrayBuffer)
}

export const deriveKeyFromPassword = async (
  password: string,
  salt: Uint8Array
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
