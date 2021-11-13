let crypto: Crypto = !globalThis?.crypto?.subtle
  ? new (require('@peculiar/webcrypto').Crypto)()
  : globalThis.crypto

export const stringToUint8Array = (str: string) => {
  return new TextEncoder().encode(str)
}

export const Uint8ArrayToString = (array: Uint8Array) => {
  return new TextDecoder('utf-8').decode(array)
}

export const arrayBufferToUint8Array = (buffer: ArrayBuffer) => {
  return new Uint8Array(buffer)
}

export const arrayBufferToArray = (buffer: ArrayBuffer) => {
  return Array.from(arrayBufferToUint8Array(buffer))
}

export const Uint8ArrayToArray = (array: Uint8Array) => {
  return Array.from(array)
}

export const arrayToUint8Array = (array: number[]) => {
  return new Uint8Array(array)
}

export const arrayToArrayBuffer = (array: number[]) => {
  return arrayToUint8Array(array).buffer
}

export const generateIV = () => {
  return crypto.getRandomValues(new Uint8Array(12))
}

export const generateSalt = () => {
  return crypto.getRandomValues(new Uint8Array(16))
}
