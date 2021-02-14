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
exports.importProtectedKeyPair = exports.exportProtectedKeyPair = exports.unlockProtectedKeyPair = exports.createProtectedKeyPair = exports.deriveKeyFromPassword = exports.deriveBitsFromPassword = exports.arrayToArrayBuffer = exports.arrayBufferToArray = exports.arrayBufferToString = exports.stringToArrayBuffer = void 0;
// Required for Node.js support
var crypto = ((_a = process === null || process === void 0 ? void 0 : process.versions) === null || _a === void 0 ? void 0 : _a.node) ? require('crypto').webcrypto
    : window.crypto;
var stringToArrayBuffer = function (str) {
    var encoder = new TextEncoder();
    return encoder.encode(str);
};
exports.stringToArrayBuffer = stringToArrayBuffer;
var arrayBufferToString = function (arrayBuffer) {
    var decoder = new TextDecoder();
    return decoder.decode(arrayBuffer);
};
exports.arrayBufferToString = arrayBufferToString;
var arrayBufferToArray = function (arrayBuffer) {
    return Array.from(new Uint8Array(arrayBuffer));
};
exports.arrayBufferToArray = arrayBufferToArray;
var arrayToArrayBuffer = function (array) {
    return new Uint8Array(array).buffer;
};
exports.arrayToArrayBuffer = arrayToArrayBuffer;
var deriveBitsFromPassword = function (password, salt) { return __awaiter(void 0, void 0, void 0, function () {
    var baseKey, derivedBits;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, crypto.subtle.importKey('raw', exports.stringToArrayBuffer(password), { name: 'PBKDF2' }, false, ['deriveBits'])];
            case 1:
                baseKey = _a.sent();
                return [4 /*yield*/, crypto.subtle.deriveBits({
                        name: 'PBKDF2',
                        hash: 'SHA-256',
                        salt: salt,
                        iterations: 100000
                    }, baseKey, 256)];
            case 2:
                derivedBits = _a.sent();
                return [2 /*return*/, derivedBits];
        }
    });
}); };
exports.deriveBitsFromPassword = deriveBitsFromPassword;
var deriveKeyFromPassword = function (password, salt) { return __awaiter(void 0, void 0, void 0, function () {
    var baseKey, derivedKey;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0: return [4 /*yield*/, crypto.subtle.importKey('raw', exports.stringToArrayBuffer(password), { name: 'PBKDF2' }, false, ['deriveKey'])];
            case 1:
                baseKey = _a.sent();
                return [4 /*yield*/, crypto.subtle.deriveKey({
                        name: 'PBKDF2',
                        hash: 'SHA-256',
                        salt: salt,
                        iterations: 100000
                    }, baseKey, {
                        name: 'AES-GCM',
                        length: 256
                    }, false, ['wrapKey', 'unwrapKey'])];
            case 2:
                derivedKey = _a.sent();
                return [2 /*return*/, derivedKey];
        }
    });
}); };
exports.deriveKeyFromPassword = deriveKeyFromPassword;
var createProtectedKeyPair = function (keyPair, password) { return __awaiter(void 0, void 0, void 0, function () {
    var salt, derivedKey, iv, wrappedPrivateKey, exportedPublicKey;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                salt = crypto.getRandomValues(new Uint8Array(16));
                return [4 /*yield*/, exports.deriveKeyFromPassword(password, salt)];
            case 1:
                derivedKey = _a.sent();
                iv = crypto.getRandomValues(new Uint8Array(12));
                return [4 /*yield*/, crypto.subtle.wrapKey('pkcs8', keyPair.privateKey, derivedKey, {
                        name: 'AES-GCM',
                        iv: iv
                    })];
            case 2:
                wrappedPrivateKey = _a.sent();
                return [4 /*yield*/, crypto.subtle.exportKey('spki', keyPair.publicKey)];
            case 3:
                exportedPublicKey = _a.sent();
                return [2 /*return*/, {
                        publicKey: exportedPublicKey,
                        privateKey: wrappedPrivateKey,
                        iv: iv,
                        salt: salt
                    }];
        }
    });
}); };
exports.createProtectedKeyPair = createProtectedKeyPair;
var unlockProtectedKeyPair = function (protectedKeyPair, password, type) { return __awaiter(void 0, void 0, void 0, function () {
    var derivedKey, unwrappedPrivateKey, keyPair;
    var _a;
    return __generator(this, function (_b) {
        switch (_b.label) {
            case 0: return [4 /*yield*/, exports.deriveKeyFromPassword(password, protectedKeyPair.salt)];
            case 1:
                derivedKey = _b.sent();
                return [4 /*yield*/, crypto.subtle.unwrapKey('pkcs8', protectedKeyPair.privateKey, derivedKey, {
                        name: 'AES-GCM',
                        iv: protectedKeyPair.iv
                    }, {
                        name: type,
                        hash: 'SHA-256'
                    }, true, type === 'RSA-OAEP' ? ['unwrapKey'] : ['sign'])];
            case 2:
                unwrappedPrivateKey = _b.sent();
                _a = {
                    privateKey: unwrappedPrivateKey
                };
                return [4 /*yield*/, crypto.subtle.importKey('spki', protectedKeyPair.publicKey, {
                        name: type,
                        hash: 'SHA-256'
                    }, true, type === 'RSA-OAEP' ? ['wrapKey'] : ['verify'])];
            case 3:
                keyPair = (_a.publicKey = _b.sent(),
                    _a);
                return [2 /*return*/, keyPair];
        }
    });
}); };
exports.unlockProtectedKeyPair = unlockProtectedKeyPair;
var exportProtectedKeyPair = function (protectedKeyPair) {
    return {
        privateKey: exports.arrayBufferToArray(protectedKeyPair.privateKey),
        publicKey: exports.arrayBufferToArray(protectedKeyPair.publicKey),
        salt: exports.arrayBufferToArray(protectedKeyPair.salt),
        iv: exports.arrayBufferToArray(protectedKeyPair.iv)
    };
};
exports.exportProtectedKeyPair = exportProtectedKeyPair;
var importProtectedKeyPair = function (exportedProtectedKeyPair) {
    return {
        privateKey: exports.arrayToArrayBuffer(exportedProtectedKeyPair.privateKey),
        publicKey: exports.arrayToArrayBuffer(exportedProtectedKeyPair.publicKey),
        salt: exports.arrayToArrayBuffer(exportedProtectedKeyPair.salt),
        iv: exports.arrayToArrayBuffer(exportedProtectedKeyPair.iv)
    };
};
exports.importProtectedKeyPair = importProtectedKeyPair;
//# sourceMappingURL=util.js.map