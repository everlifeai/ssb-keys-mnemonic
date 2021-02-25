"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var bip39 = require("bip39");
var chloride = require('chloride');
function keysToWords(keys) {
    if (keys.curve !== 'ed25519')
        throw new Error('only ed25519 is supported');
    if (!keys.public)
        throw new Error('keys object is missing .public field');
    if (!keys.private)
        throw new Error('keys object is missing .private field');
    var pub = Buffer.from(keys.public.replace(/\.ed25519$/, ''), 'base64');
    var priv = Buffer.from(keys.private.replace(/\.ed25519$/, ''), 'base64');
    if (pub.length !== 32)
        throw new Error('public should be exactly 32 bytes');
    if (priv.length !== 64)
        throw new Error('private should be exactly 64 bytes');
    if (pub.compare(priv, 32, 64, 0, 32) !== 0) {
        throw new Error('public ed2519 key must be embedded within private key');
    }
    var seed = priv.slice(0, 32);
    var words = bip39.entropyToMnemonic(seed);
    return words;
}
exports.keysToWords = keysToWords;
function wordsToKeys(words) {
    var wordArr = words.trim().split(/\s+/g);
    var amount = wordArr.length;
    if (amount < 24  || amount > 24)
        throw new Error('there should be 24 words');
    const fixedWords = wordArr.slice(0, 24).join(' ');
    if (!bip39.validateMnemonic(fixedWords))
        throw new Error('invalid words');
    var seed =  Buffer.from(bip39.mnemonicToEntropy(words));
    
    var _a = chloride.crypto_sign_seed_keypair(seed), publicKey = _a.publicKey, secretKey = _a.secretKey;
    var _public = publicKey.toString('base64') + '.ed25519';
    var _private = secretKey.toString('base64') + '.ed25519';
    var keys = {
        curve: 'ed25519',
        public: _public,
        private: _private,
        id: '@' + _public,
    };
    return keys;
}
exports.wordsToKeys = wordsToKeys;
