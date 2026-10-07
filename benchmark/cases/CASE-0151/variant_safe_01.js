/**
 * data encrypt/decrypt
 *
 * New format: 'v2.<base64(salt(16) | iv(12) | authtag(16) | ciphertext)>' (aes-256-gcm)
 * Legacy format: pure hex (aes-192-cbc, static iv and salt), decrypt only.
 */

const algorithmDefault = 'aes-256-gcm'
const SALT_LENGTH = 16
const IV_LENGTH = 12
const TAG_LENGTH = 16
const KEY_LENGTH = 32
const PREFIX = 'v2.'

function scryptAsync (...args) {
  const crypto = require('crypto')
  return new Promise((resolve, reject) =>
    crypto.scrypt(...args, (err, result) => {
      if (err) {
        reject(err)
      }
      resolve(result)
    })
  )
}

function seal (str, key, salt, algorithm) {
  const crypto = require('crypto')
  const iv = crypto.randomBytes(IV_LENGTH)
  const cipher = crypto.createCipheriv(algorithm, key, iv)
  const body = Buffer.concat([cipher.update(str, 'utf8'), cipher.final()])
  return PREFIX + Buffer.concat([salt, iv, cipher.getAuthTag(), body]).toString('base64')
}

function unpack (encrypted) {
  const raw = Buffer.from(encrypted.slice(PREFIX.length), 'base64')
  return {
    salt: raw.subarray(0, SALT_LENGTH),
    iv: raw.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH),
    tag: raw.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH),
    body: raw.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH)
  }
}

function open (parts, key, algorithm) {
  const crypto = require('crypto')
  const decipher = crypto.createDecipheriv(algorithm, key, parts.iv)
  decipher.setAuthTag(parts.tag)
  return Buffer.concat([decipher.update(parts.body), decipher.final()]).toString('utf8')
}

function legacyDecrypt (encrypted, key) {
  const crypto = require('crypto')
  const decipher = crypto.createDecipheriv('aes-192-cbc', key, Buffer.alloc(16, 0))
  let decrypted = decipher.update(encrypted, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  return decrypted
}

exports.encrypt = function (
  str = '',
  password,
  algorithm = algorithmDefault
) {
  const crypto = require('crypto')
  const salt = crypto.randomBytes(SALT_LENGTH)
  const key = crypto.scryptSync(password, salt, KEY_LENGTH)
  return seal(str, key, salt, algorithm)
}

exports.decrypt = function (
  encrypted = '',
  password,
  algorithm = algorithmDefault
) {
  const crypto = require('crypto')
  if (!encrypted.startsWith(PREFIX)) {
    return legacyDecrypt(encrypted, crypto.scryptSync(password, 'salt', 24))
  }
  const parts = unpack(encrypted)
  const key = crypto.scryptSync(password, parts.salt, KEY_LENGTH)
  return open(parts, key, algorithm)
}

exports.encryptAsync = async function (
  str = '',
  password,
  algorithm = algorithmDefault
) {
  const crypto = require('crypto')
  const salt = crypto.randomBytes(SALT_LENGTH)
  const key = await scryptAsync(password, salt, KEY_LENGTH)
  return seal(str, key, salt, algorithm)
}

exports.decryptAsync = async function (
  encrypted = '',
  password,
  algorithm = algorithmDefault
) {
  if (!encrypted.startsWith(PREFIX)) {
    return legacyDecrypt(encrypted, await scryptAsync(password, 'salt', 24))
  }
  const parts = unpack(encrypted)
  const key = await scryptAsync(password, parts.salt, KEY_LENGTH)
  return open(parts, key, algorithm)
}
