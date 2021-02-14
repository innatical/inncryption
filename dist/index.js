"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
exports.importProtectedKeychain = exports.exportProtectedKeychain = exports.importPublicKey = exports.unlockProtectedKeychain = exports.createProtectedKeychain = exports.generateKeychain = exports.verifyMessage = exports.signMessage = exports.decryptMessage = exports.encryptMessage = void 0;
var util_1 = require("./util");
// Required for Node.js support
var crypto = ((_a = process === null || process === void 0 ? void 0 : process.versions) === null || _a === void 0 ? void 0 : _a.node) ? require('crypto').webcrypto
    : window.crypto;
/**
 * Encrypts and signs a message
 * @param keychain The sender's keychain
 * @param publicEncryptionKey The recipient's public encryption key
 * @param message The message to encrypt
 * @returns The encrypted and signed message
 */
var encryptMessage = function (keychain, publicEncryptionKey, message) { return __awaiter(void 0, void 0, void 0, function () {
    var sessionKey, wrappedKey, iv, encryptedData;
    var _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0: return [4 /*yield*/, crypto.subtle.generateKey({
                    name: 'AES-GCM',
                    length: 256
                }, true, ['encrypt'])];
            case 1:
                sessionKey = _b.sent();
                return [4 /*yield*/, crypto.subtle.wrapKey('raw', sessionKey, publicEncryptionKey, {
                        name: 'RSA-OAEP'
                    })];
            case 2:
                wrappedKey = _b.sent();
                iv = crypto.getRandomValues(new Uint8Array(12));
                return [4 /*yield*/, crypto.subtle.encrypt({
                        name: 'AES-GCM',
                        iv: iv
                    }, sessionKey, util_1.stringToArrayBuffer(message))];
            case 3:
                encryptedData = _b.sent();
                _a = {
                    key: wrappedKey,
                    data: encryptedData,
                    iv: iv
                };
                return [4 /*yield*/, exports.signMessage(keychain, message)];
            case 4: return [2 /*return*/, (_a.signature = (_b.sent()).signature,
                    _a)];
        }
    });
}); };
exports.encryptMessage = encryptMessage;
/**
 * Decrypts and verifies the signature of a message
 * @param keychain The recipient's keychain
 * @param publicSigningKey The sender's public signing key
 * @return The unencrypted and verified message
 */
var decryptMessage = function (keychain, publicSigningKey, data) { return __awaiter(void 0, void 0, void 0, function () {
    var sessionKey, iv, decryptedData, message;
    var _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0: return [4 /*yield*/, crypto.subtle.unwrapKey('raw', data.key, keychain.encryptionKeyPair.privateKey, {
                    name: 'RSA-OAEP'
                }, {
                    name: 'AES-GCM'
                }, true, ['decrypt'])];
            case 1:
                sessionKey = _b.sent();
                iv = data.iv;
                return [4 /*yield*/, crypto.subtle.decrypt({
                        name: 'AES-GCM',
                        iv: iv
                    }, sessionKey, data.data)];
            case 2:
                decryptedData = _b.sent();
                message = util_1.arrayBufferToString(decryptedData);
                _a = {
                    message: message
                };
                return [4 /*yield*/, exports.verifyMessage({
                        signature: data.signature,
                        data: decryptedData
                    }, publicSigningKey)];
            case 3: return [2 /*return*/, (_a.verified = (_b.sent()).verified,
                    _a)];
        }
    });
}); };
exports.decryptMessage = decryptMessage;
var signMessage = function (keychain, message) { return __awaiter(void 0, void 0, void 0, function () {
    var signature;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, crypto.subtle.sign({
                    name: 'RSA-PSS',
                    saltLength: 32
                }, keychain.signingKeyPair.privateKey, util_1.stringToArrayBuffer(message))];
            case 1:
                signature = _a.sent();
                return [2 /*return*/, {
                        data: util_1.stringToArrayBuffer(message),
                        signature: signature
                    }];
        }
    });
}); };
exports.signMessage = signMessage;
var verifyMessage = function (message, publicKey) { return __awaiter(void 0, void 0, void 0, function () {
    var verified;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, crypto.subtle.verify({
                    name: 'RSA-PSS',
                    saltLength: 32
                }, publicKey, message.signature, message.data)];
            case 1:
                verified = _a.sent();
                return [2 /*return*/, {
                        verified: verified,
                        message: util_1.arrayBufferToString(message.data)
                    }];
        }
    });
}); };
exports.verifyMessage = verifyMessage;
/**
 * Generates a new {@link Keychain} used for encrypting session keys and signing
 * @param password The password to generate the {@link authenticationToken} with
 */
var generateKeychain = function (password) { return __awaiter(void 0, void 0, void 0, function () {
    var encryptionKeyPair, signingKeyPair, tokenSalt, authenticationToken;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, crypto.subtle.generateKey({
                    name: 'RSA-OAEP',
                    modulusLength: 4096,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256'
                }, true, ['unwrapKey', 'wrapKey'])];
            case 1:
                encryptionKeyPair = _a.sent();
                return [4 /*yield*/, crypto.subtle.generateKey({
                        name: 'RSA-PSS',
                        modulusLength: 4096,
                        publicExponent: new Uint8Array([1, 0, 1]),
                        hash: 'SHA-256'
                    }, true, ['sign', 'verify'])];
            case 2:
                signingKeyPair = _a.sent();
                tokenSalt = crypto.getRandomValues(new Uint8Array(16));
                return [4 /*yield*/, util_1.deriveBitsFromPassword(password, tokenSalt)];
            case 3:
                authenticationToken = _a.sent();
                return [2 /*return*/, {
                        encryptionKeyPair: encryptionKeyPair,
                        signingKeyPair: signingKeyPair,
                        authenticationToken: authenticationToken,
                        tokenSalt: tokenSalt
                    }];
        }
    });
}); };
exports.generateKeychain = generateKeychain;
/**
 * Creates a protected keychain to upload to a keyserver
 * @param keychain The user's keychain
 * @param password The password to protect the keychain with
 */
var createProtectedKeychain = function (keychain, password) { return __awaiter(void 0, void 0, void 0, function () {
    var _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _a = {};
                return [4 /*yield*/, util_1.createProtectedKeyPair(keychain.encryptionKeyPair, password)];
            case 1:
                _a.encryption = _b.sent();
                return [4 /*yield*/, util_1.createProtectedKeyPair(keychain.signingKeyPair, password)];
            case 2: return [2 /*return*/, (_a.signing = _b.sent(),
                    _a.tokenSalt = keychain.tokenSalt,
                    _a)];
        }
    });
}); };
exports.createProtectedKeychain = createProtectedKeychain;
/**
 * Unlocks a protected keychain with the user's password
 * @param protectedKeychain The user's protected keychain
 * @param password The password used to protect the keychain
 */
var unlockProtectedKeychain = function (protectedKeychain, password) { return __awaiter(void 0, void 0, void 0, function () {
    var _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                _a = {};
                return [4 /*yield*/, util_1.unlockProtectedKeyPair(protectedKeychain.encryption, password, 'RSA-OAEP')];
            case 1:
                _a.encryptionKeyPair = _b.sent();
                return [4 /*yield*/, util_1.unlockProtectedKeyPair(protectedKeychain.signing, password, 'RSA-PSS')];
            case 2:
                _a.signingKeyPair = _b.sent();
                return [4 /*yield*/, util_1.deriveBitsFromPassword(password, protectedKeychain.tokenSalt)];
            case 3: return [2 /*return*/, (_a.authenticationToken = _b.sent(),
                    _a.tokenSalt = protectedKeychain.tokenSalt,
                    _a)];
        }
    });
}); };
exports.unlockProtectedKeychain = unlockProtectedKeychain;
/**
 * Imports another user's public key
 * @param publicKey The other user's public key
 * @param type The type of public key
 */
var importPublicKey = function (publicKey, type) { return __awaiter(void 0, void 0, void 0, function () {
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, crypto.subtle.importKey('spki', util_1.arrayToArrayBuffer(publicKey), {
                    name: type === 'encryption' ? 'RSA-OAEP' : 'RSA-PSS',
                    hash: 'SHA-256'
                }, true, type === 'encryption' ? ['wrapKey'] : ['verify'])];
            case 1: return [2 /*return*/, _a.sent()];
        }
    });
}); };
exports.importPublicKey = importPublicKey;
var exportProtectedKeychain = function (protectedKeychain) {
    return {
        encryption: util_1.exportProtectedKeyPair(protectedKeychain.encryption),
        signing: util_1.exportProtectedKeyPair(protectedKeychain.signing),
        tokenSalt: util_1.arrayBufferToArray(protectedKeychain.tokenSalt)
    };
};
exports.exportProtectedKeychain = exportProtectedKeychain;
var importProtectedKeychain = function (exportedProtectedKeychain) {
    return {
        encryption: util_1.importProtectedKeyPair(exportedProtectedKeychain.encryption),
        signing: util_1.importProtectedKeyPair(exportedProtectedKeychain.signing),
        tokenSalt: new Uint8Array(exportedProtectedKeychain.tokenSalt)
    };
};
exports.importProtectedKeychain = importProtectedKeychain;
//# sourceMappingURL=index.js.map