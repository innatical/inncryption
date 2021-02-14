import { EncryptedMessage, ExportedProtectedKeychain, Keychain, ProtectedKeychain, SignedMessage, VerifiedMessage } from './types';
export { EncryptedMessage, ProtectedKeychain };
/**
 * Encrypts and signs a message
 * @param keychain The sender's keychain
 * @param publicEncryptionKey The recipient's public encryption key
 * @param message The message to encrypt
 * @returns The encrypted and signed message
 */
export declare const encryptMessage: (keychain: Keychain, publicEncryptionKey: CryptoKey, message: string) => Promise<EncryptedMessage>;
/**
 * Decrypts and verifies the signature of a message
 * @param keychain The recipient's keychain
 * @param publicSigningKey The sender's public signing key
 * @return The unencrypted and verified message
 */
export declare const decryptMessage: (keychain: Keychain, publicSigningKey: CryptoKey, data: EncryptedMessage) => Promise<VerifiedMessage>;
export declare const signMessage: (keychain: Keychain, message: string) => Promise<SignedMessage>;
export declare const verifyMessage: (message: SignedMessage, publicKey: CryptoKey) => Promise<VerifiedMessage>;
/**
 * Generates a new {@link Keychain} used for encrypting session keys and signing
 * @param password The password to generate the {@link authenticationToken} with
 */
export declare const generateKeychain: (password: string) => Promise<Keychain>;
/**
 * Creates a protected keychain to upload to a keyserver
 * @param keychain The user's keychain
 * @param password The password to protect the keychain with
 */
export declare const createProtectedKeychain: (keychain: Keychain, password: string) => Promise<ProtectedKeychain>;
/**
 * Unlocks a protected keychain with the user's password
 * @param protectedKeychain The user's protected keychain
 * @param password The password used to protect the keychain
 */
export declare const unlockProtectedKeychain: (protectedKeychain: ProtectedKeychain, password: string) => Promise<Keychain>;
/**
 * Imports another user's public key
 * @param publicKey The other user's public key
 * @param type The type of public key
 */
export declare const importPublicKey: (publicKey: number[], type: 'encryption' | 'signing') => Promise<CryptoKey>;
export declare const exportProtectedKeychain: (protectedKeychain: ProtectedKeychain) => ExportedProtectedKeychain;
export declare const importProtectedKeychain: (exportedProtectedKeychain: ExportedProtectedKeychain) => ProtectedKeychain;
