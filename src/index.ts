import crypto from '@innatical/isomorphic-webcrypto'
import {
  arrayBufferToArray,
  arrayBufferToUint8Array,
  arrayToArrayBuffer,
  arrayToUint8Array,
  generateIV,
  stringToUint8Array,
  Uint8ArrayToArray,
  Uint8ArrayToString,
  generateSalt
} from './util'

// Interfaces

/**
 * A message signed with a SignedPair
 */
export interface SignedMessage {
  data: string
  signature: number[]
}

/**
 * A message encrypted with a SymmetricalKey
 */
export interface EncryptedMessage {
  data: number[]
  iv: number[]
}

/**
 * A pair of JsonWebKeys
 */
export interface JsonWebKeyPair {
  publicKey: JsonWebKey
  privateKey: JsonWebKey
}

/**
 * A keychain of JsonWebKeyPairs and JsonWebKeys
 */
export interface JsonWebKeyChain {
  personal: JsonWebKey
  signing: JsonWebKeyPair
  encryption: JsonWebKeyPair
}

/**
 * A keychain of public JsonWebKeys
 */
export interface JsonWebKeyPublicChain {
  signing: JsonWebKey
  encryption: JsonWebKey
}

// Classes

/**
 * A SymmetricKey is used to encrypt data that can be decrypted with the same SymmetricKey for later use
 */
export class SymmetricKey {
  private key: CryptoKey

  constructor(key: CryptoKey) {
    this.key = key
  }

  /**
   * Encrypts a JSON object with this key
   * @param message The message to encrypt, must be JSON serializable
   * @returns A message encrypted with this key
   */
  async encrypt(message: any): Promise<EncryptedMessage> {
    const data = JSON.stringify(message)
    const iv = generateIV()

    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      this.key,
      stringToUint8Array(data)
    )

    return {
      iv: Uint8ArrayToArray(iv),
      data: arrayBufferToArray(encrypted)
    }
  }

  /**
   * Decrypts an EncryptedMessage encrypted with this key
   * @param message The EncryptedMessage to decrypt
   * @returns The unserialized, unencrypted data
   */
  async decrypt(message: EncryptedMessage): Promise<unknown> {
    const buffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: arrayToUint8Array(message.iv)
      },
      this.key,
      arrayToArrayBuffer(message.data)
    )

    return JSON.parse(Uint8ArrayToString(arrayBufferToUint8Array(buffer)))
  }

  /**
   * Export this key as a JsonWebKey
   * @returns A JsonWebKey
   */
  async toJWK(): Promise<JsonWebKey> {
    return await crypto.subtle.exportKey('jwk', this.key)
  }

  /**
   * Import a JsonWebKey
   * @param key A JsonWebKey
   * @returns A SymmetricKey converted from the JsonWebKey
   */
  static async fromJWK(key: JsonWebKey) {
    const imported = await crypto.subtle.importKey(
      'jwk',
      key,
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    )

    return new SymmetricKey(imported)
  }

  /**
   * Generate a new SymmmetricKey
   * @returns A new, unique, SymmmetricKey
   */
  static async generate() {
    const key = await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    )

    return new SymmetricKey(key)
  }

  /**
   * Generate a salt that can be used with the generateFromPassword method
   * @returns A random salt
   */
  static generateSalt() {
    return Uint8ArrayToArray(generateSalt())
  }

  /**
   * Generate a SymmmetricKey using a password and salt
   * @returns A SymmmetricKey derived from the supplied password and salt
   */
  static async generateFromPassword(password: string, salt: number[]) {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      stringToUint8Array(password),
      { name: 'PBKDF2' },
      true,
      ['deriveKey']
    )

    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: arrayToUint8Array(salt),
        iterations: 100000
      },
      baseKey,
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['wrapKey', 'unwrapKey']
    )

    return new SymmetricKey(derivedKey)
  }
}

/**
 * A SigningPair allows you to sign and verify messages
 */
export class SigningPair {
  private pair: CryptoKeyPair

  constructor(pair: CryptoKeyPair) {
    this.pair = pair
  }

  /**
   * Sign a message
   * @param message The message to sign, must be JSON serializable
   * @returns A SignedMessage
   */
  async sign(message: any): Promise<SignedMessage> {
    const data = JSON.stringify(message)
    const signature = await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: 'SHA-512'
      },
      this.pair.privateKey!,
      stringToUint8Array(data)
    )

    return {
      data,
      signature: arrayBufferToArray(signature)
    }
  }

  /**
   * Verify a message using a JsonWebKey and the signed message
   * @param message The SignedMessage to verify
   * @param key The public JsonWebKey to verify against
   * @returns A status code and message if it could be verifies
   */
  static async verify(
    message: SignedMessage,
    key: JsonWebKey
  ): Promise<{ ok: false } | { ok: true; message: unknown }> {
    const imported = await crypto.subtle.importKey(
      'jwk',
      key,
      {
        name: 'ECDSA',
        namedCurve: 'P-521'
      },
      true,
      ['verify']
    )

    const valid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-512'
      },
      imported,
      arrayToUint8Array(message.signature),
      stringToUint8Array(message.data)
    )

    if (valid) {
      return {
        ok: true,
        message: JSON.parse(message.data)
      }
    } else {
      return {
        ok: false
      }
    }
  }

  /**
   * Generate a new SigningPair
   * @returns A new, unique SigningPair
   */
  static async generate() {
    const signing = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-521'
      },
      true,
      ['sign', 'verify']
    )

    return new SigningPair(signing)
  }

  /**
   * Export as a JsonWebKeyPair
   * @returns A JsonWebKeyPair
   */
  async toJWKPair(): Promise<JsonWebKeyPair> {
    return {
      publicKey: await crypto.subtle.exportKey('jwk', this.pair.publicKey!),
      privateKey: await crypto.subtle.exportKey('jwk', this.pair.privateKey!)
    }
  }

  /**
   * Import from a JsonWebKeyPair
   * @param pair A JsonWebKeyPair
   * @returns The imported SigningPair
   */
  static async fromJWKPair(pair: JsonWebKeyPair) {
    return new SigningPair({
      publicKey: await crypto.subtle.importKey(
        'jwk',
        pair.publicKey,
        {
          name: 'ECDSA',
          namedCurve: 'P-521'
        },
        true,
        ['verify']
      ),
      privateKey: await crypto.subtle.importKey(
        'jwk',
        pair.privateKey,
        {
          name: 'ECDSA',
          namedCurve: 'P-521'
        },
        true,
        ['sign']
      )
    })
  }
}

/**
 * A EncryptionPair allows you to generate session keys for encrypting and decrypting messages to other users
 */
export class EncryptionPair {
  private pair: CryptoKeyPair

  constructor(pair: CryptoKeyPair) {
    this.pair = pair
  }

  /**
   * Generate a session key from another user's public key
   * @param publicKey The other user's public key
   * @returns A session key which can be used to encrypt and decrypt messages to the other user
   */
  async sessionKey(publicKey: JsonWebKey) {
    const otherKey = await crypto.subtle.importKey(
      'jwk',
      publicKey,
      {
        name: 'ECDH',
        namedCurve: 'P-521'
      },
      true,
      []
    )

    const result = await crypto.subtle.deriveKey(
      {
        name: 'ECDH',
        public: otherKey
      },
      this.pair.privateKey!,
      {
        name: 'AES-GCM',
        length: 256
      },
      true,
      ['encrypt', 'decrypt']
    )

    return new SymmetricKey(result)
  }

  /**
   * Generate a new EncryptionPair
   * @returns A new, unique EncryptionPair
   */
  static async generate() {
    const encryption = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-521'
      },
      true,
      ['deriveKey']
    )

    return new EncryptionPair(encryption)
  }

  /**
   * Export as a JsonWebKeyPair
   * @returns A JsonWebKeyPair
   */
  async toJWKPair(): Promise<JsonWebKeyPair> {
    return {
      publicKey: await crypto.subtle.exportKey('jwk', this.pair.publicKey!),
      privateKey: await crypto.subtle.exportKey('jwk', this.pair.privateKey!)
    }
  }

  /**
   * Import from a JsonWebKeyPair
   * @param pair A JsonWebKeyPair
   * @returns The imported EncryptionPair
   */
  static async fromJWKPair(pair: JsonWebKeyPair) {
    return new EncryptionPair({
      publicKey: await crypto.subtle.importKey(
        'jwk',
        pair.publicKey,
        {
          name: 'ECDH',
          namedCurve: 'P-521'
        },
        true,
        []
      ),
      privateKey: await crypto.subtle.importKey(
        'jwk',
        pair.privateKey,
        {
          name: 'ECDH',
          namedCurve: 'P-521'
        },
        true,
        ['deriveKey']
      )
    })
  }
}

/**
 * A Keychain holds keys and keypairs used for signing and encryption. It is a high-level interface for managing other components
 */
export class Keychain {
  encryption: EncryptionPair
  signing: SigningPair
  personal: SymmetricKey

  constructor(
    encryption: EncryptionPair,
    signing: SigningPair,
    personal: SymmetricKey
  ) {
    this.encryption = encryption
    this.signing = signing
    this.personal = personal
  }

  /**
   * Export as a JsonWebKeyChain
   * @returns A JsonWebKeyChain
   */
  async toJWKChain(): Promise<JsonWebKeyChain> {
    return {
      personal: await this.personal.toJWK(),
      encryption: await this.encryption.toJWKPair(),
      signing: await this.encryption.toJWKPair()
    }
  }

  /**
   * Export as a JsonWebKeyPublicChain, which can be shared with others for encryption and signing purposes
   * @returns A JsonWebKeyPublicChain
   */
  async toJWKPublicChain(): Promise<JsonWebKeyPublicChain> {
    return {
      encryption: (await this.encryption.toJWKPair()).publicKey,
      signing: (await this.encryption.toJWKPair()).publicKey
    }
  }

  /**
   * Import a JsonWebKeyChain
   * @param chain A JsonWebKeyChain to import
   * @returns The imported Keychain
   */
  static async fromJWKChain(chain: JsonWebKeyChain) {
    return new Keychain(
      await EncryptionPair.fromJWKPair(chain.encryption),
      await SigningPair.fromJWKPair(chain.signing),
      await SymmetricKey.fromJWK(chain.personal)
    )
  }

  /**
   * Generate a Keychain
   * @returns A new, unique keychain
   */
  static async generate() {
    const encryption = await EncryptionPair.generate()
    const signing = await SigningPair.generate()
    const personal = await SymmetricKey.generate()

    return new Keychain(encryption, signing, personal)
  }
}
