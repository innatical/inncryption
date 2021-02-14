"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
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
Object.defineProperty(exports, "__esModule", { value: true });
var inncrypt = __importStar(require("."));
var util_1 = require("./util");
test('signs and verifies', function () { return __awaiter(void 0, void 0, void 0, function () {
    var message, password, keychain, signedMessage, _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                message = 'Octii is a chat service by Innatical, focusing on simplicity, privacy, and extensibility.';
                password = 'password';
                return [4 /*yield*/, inncrypt.generateKeychain(password)];
            case 1:
                keychain = _b.sent();
                return [4 /*yield*/, inncrypt.signMessage(keychain, message)];
            case 2:
                signedMessage = _b.sent();
                _a = expect;
                return [4 /*yield*/, inncrypt.verifyMessage(signedMessage, keychain.signingKeyPair.publicKey)];
            case 3:
                _a.apply(void 0, [_b.sent()]).toStrictEqual({
                    verified: true,
                    message: message
                });
                return [2 /*return*/];
        }
    });
}); }, 10000);
test('protects and unlocks keychains', function () { return __awaiter(void 0, void 0, void 0, function () {
    var crypto, password, keychain, protectedKeychain, unlockedKeychain, _a, _b, _c, _d, _e;
    var _f;
    return __generator(this, function (_g) {
        switch (_g.label) {
            case 0:
                crypto = ((_f = process === null || process === void 0 ? void 0 : process.versions) === null || _f === void 0 ? void 0 : _f.node) ? require('crypto').webcrypto
                    : window.crypto;
                password = 'password';
                return [4 /*yield*/, inncrypt.generateKeychain(password)];
            case 1:
                keychain = _g.sent();
                return [4 /*yield*/, inncrypt.createProtectedKeychain(keychain, password)];
            case 2:
                protectedKeychain = _g.sent();
                return [4 /*yield*/, inncrypt.unlockProtectedKeychain(protectedKeychain, password)];
            case 3:
                unlockedKeychain = _g.sent();
                _b = expect;
                return [4 /*yield*/, crypto.subtle.exportKey('spki', unlockedKeychain.encryptionKeyPair.publicKey)];
            case 4:
                _c = [
                    _g.sent()
                ];
                return [4 /*yield*/, crypto.subtle.exportKey('pkcs8', unlockedKeychain.encryptionKeyPair.privateKey)];
            case 5:
                _c = _c.concat([
                    _g.sent()
                ]);
                return [4 /*yield*/, crypto.subtle.exportKey('spki', unlockedKeychain.signingKeyPair.publicKey)];
            case 6:
                _c = _c.concat([
                    _g.sent()
                ]);
                return [4 /*yield*/, crypto.subtle.exportKey('pkcs8', unlockedKeychain.signingKeyPair.privateKey)];
            case 7:
                _d = (_a = _b.apply(void 0, [_c.concat([
                        _g.sent(),
                        unlockedKeychain.authenticationToken
                    ])])).toStrictEqual;
                return [4 /*yield*/, crypto.subtle.exportKey('spki', keychain.encryptionKeyPair.publicKey)];
            case 8:
                _e = [
                    _g.sent()
                ];
                return [4 /*yield*/, crypto.subtle.exportKey('pkcs8', keychain.encryptionKeyPair.privateKey)];
            case 9:
                _e = _e.concat([
                    _g.sent()
                ]);
                return [4 /*yield*/, crypto.subtle.exportKey('spki', keychain.signingKeyPair.publicKey)];
            case 10:
                _e = _e.concat([
                    _g.sent()
                ]);
                return [4 /*yield*/, crypto.subtle.exportKey('pkcs8', keychain.signingKeyPair.privateKey)];
            case 11:
                _d.apply(_a, [_e.concat([
                        _g.sent(),
                        keychain.authenticationToken
                    ])]);
                return [2 /*return*/];
        }
    });
}); }, 10000);
test('encrypts and decrypts', function () { return __awaiter(void 0, void 0, void 0, function () {
    var message, password, sender, recipient, encryptedMessage, decryptedMessage;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                message = 'Octii is a chat service by Innatical, focusing on simplicity, privacy, and extensibility.';
                password = 'password';
                return [4 /*yield*/, inncrypt.generateKeychain(password)];
            case 1:
                sender = _a.sent();
                return [4 /*yield*/, inncrypt.generateKeychain(password)];
            case 2:
                recipient = _a.sent();
                return [4 /*yield*/, inncrypt.encryptMessage(sender, recipient.encryptionKeyPair.publicKey, message)];
            case 3:
                encryptedMessage = _a.sent();
                return [4 /*yield*/, inncrypt.decryptMessage(recipient, sender.signingKeyPair.publicKey, encryptedMessage)];
            case 4:
                decryptedMessage = _a.sent();
                expect(decryptedMessage).toStrictEqual({
                    verified: true,
                    message: message
                });
                return [2 /*return*/];
        }
    });
}); }, 10000);
test('generates authenticationToken', function () { return __awaiter(void 0, void 0, void 0, function () {
    var crypto, password, keychain, baseKey, _a, _b;
    var _c;
    return __generator(this, function (_d) {
        switch (_d.label) {
            case 0:
                crypto = ((_c = process === null || process === void 0 ? void 0 : process.versions) === null || _c === void 0 ? void 0 : _c.node) ? require('crypto').webcrypto
                    : window.crypto;
                password = 'password';
                return [4 /*yield*/, inncrypt.generateKeychain(password)];
            case 1:
                keychain = _d.sent();
                return [4 /*yield*/, crypto.subtle.importKey('raw', util_1.stringToArrayBuffer(password), { name: 'PBKDF2' }, false, ['deriveBits'])];
            case 2:
                baseKey = _d.sent();
                _b = (_a = expect(keychain.authenticationToken)).toStrictEqual;
                return [4 /*yield*/, crypto.subtle.deriveBits({
                        name: 'PBKDF2',
                        hash: 'SHA-256',
                        salt: keychain.tokenSalt,
                        iterations: 100000
                    }, baseKey, 256)];
            case 3:
                _b.apply(_a, [_d.sent()]);
                return [2 /*return*/];
        }
    });
}); });
test('exports and imports', function () { return __awaiter(void 0, void 0, void 0, function () {
    var crypto, password, keychain, protectedKeychain, exportedProtectedKeychain, importedProtectedKeychain;
    var _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0:
                crypto = ((_a = process === null || process === void 0 ? void 0 : process.versions) === null || _a === void 0 ? void 0 : _a.node) ? require('crypto').webcrypto
                    : window.crypto;
                password = 'password';
                return [4 /*yield*/, inncrypt.generateKeychain(password)];
            case 1:
                keychain = _b.sent();
                return [4 /*yield*/, inncrypt.createProtectedKeychain(keychain, password)];
            case 2:
                protectedKeychain = _b.sent();
                exportedProtectedKeychain = inncrypt.exportProtectedKeychain(protectedKeychain);
                importedProtectedKeychain = inncrypt.importProtectedKeychain(exportedProtectedKeychain);
                expect([
                    util_1.arrayToArrayBuffer(exportedProtectedKeychain.encryption.publicKey),
                    util_1.arrayToArrayBuffer(exportedProtectedKeychain.encryption.privateKey),
                    util_1.arrayToArrayBuffer(exportedProtectedKeychain.encryption.salt),
                    util_1.arrayToArrayBuffer(exportedProtectedKeychain.encryption.iv),
                    util_1.arrayToArrayBuffer(exportedProtectedKeychain.signing.publicKey),
                    util_1.arrayToArrayBuffer(exportedProtectedKeychain.signing.privateKey),
                    util_1.arrayToArrayBuffer(exportedProtectedKeychain.signing.salt),
                    util_1.arrayToArrayBuffer(exportedProtectedKeychain.signing.iv),
                    new Uint8Array(exportedProtectedKeychain.tokenSalt)
                ]).toStrictEqual([
                    importedProtectedKeychain.encryption.publicKey,
                    importedProtectedKeychain.encryption.privateKey,
                    importedProtectedKeychain.encryption.salt,
                    importedProtectedKeychain.encryption.iv,
                    importedProtectedKeychain.signing.publicKey,
                    importedProtectedKeychain.signing.privateKey,
                    importedProtectedKeychain.signing.salt,
                    importedProtectedKeychain.signing.iv,
                    importedProtectedKeychain.tokenSalt
                ]);
                return [2 /*return*/];
        }
    });
}); });
//# sourceMappingURL=index.test.js.map