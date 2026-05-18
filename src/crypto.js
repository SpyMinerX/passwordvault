'use strict';

const crypto = require('crypto');
const config = require('./config');

let _masterKey;

function getMasterKey() {
  if (!_masterKey) {
    _masterKey = Buffer.from(config.masterKey, 'hex');
    if (_masterKey.length !== 32) throw new Error('MASTER_KEY must decode to exactly 32 bytes');
  }
  return _masterKey;
}

function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined || plaintext === '') {
    return { ciphertext: null, iv: null };
  }
  const key = getMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Store: base64(16-byte tag + ciphertext)
  const combined = Buffer.concat([tag, encrypted]);
  return {
    ciphertext: combined.toString('base64'),
    iv: iv.toString('base64'),
  };
}

function decrypt(ciphertextB64, ivB64) {
  if (!ciphertextB64 || !ivB64) return '';
  const key = getMasterKey();
  const iv = Buffer.from(ivB64, 'base64');
  const combined = Buffer.from(ciphertextB64, 'base64');
  const tag = combined.subarray(0, 16);
  const ciphertext = combined.subarray(16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function computeHmac(plaintext) {
  if (!plaintext) return null;
  return crypto.createHmac('sha256', getMasterKey()).update(plaintext, 'utf8').digest('hex');
}

function scoreStrength(password) {
  if (!password) return 'none';
  const missing = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/].filter(r => !r.test(password)).length;
  if (password.length < 8 || missing >= 3) return 'weak';
  if (password.length < 12 || missing > 0) return 'fair';
  return 'strong';
}

module.exports = { encrypt, decrypt, computeHmac, scoreStrength };
