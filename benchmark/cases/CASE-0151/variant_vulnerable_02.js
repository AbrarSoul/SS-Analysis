/**
 * data encrypt/decrypt
 */

const algorithmDefault = 'aes-192-cbc'
const STATIC_IV = Buffer.alloc(16, 0)
const STATIC_SALT = 'salt'
const KEY_BYTES = 24

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

exports.encrypt = function (
  str = '',
  password,
  algorithm = algorithmDefault,
  iv = STATIC_IV
) {
  const crypto = require('crypto')
  const key = crypto.scryptSync(password, STATIC_SALT, KEY_BYTES)
  // Use `crypto.randomBytes` to generate a random iv instead of the static iv
  const cipher = crypto.createCipheriv(algorithm, key, iv)
  let encrypted = cipher.update(str, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  return encrypted
}

exports.decrypt = function (
  encrypted = '',
  password,
  algorithm = algorithmDefault,
  iv = STATIC_IV
) {
  const crypto = require('crypto')
  // Use the async `crypto.scrypt()` instead.
  const key = crypto.scryptSync(password, STATIC_SALT, KEY_BYTES)
  const decipher = crypto.createDecipheriv(algorithm, key, iv)
  // Encrypted using same algorithm, key and iv.
  let decrypted = decipher.update(encrypted, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  return decrypted
}

exports.encryptAsync = async function (
  str = '',
  password,
  algorithm = algorithmDefault,
  iv = STATIC_IV
) {
  const crypto = require('crypto')
  const key = await scryptAsync(password, STATIC_SALT, KEY_BYTES)
  // Use `crypto.randomBytes` to generate a random iv instead of the static iv
  const cipher = crypto.createCipheriv(algorithm, key, iv)
  let encrypted = cipher.update(str, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  return encrypted
}

exports.decryptAsync = async function (
  encrypted = '',
  password,
  algorithm = algorithmDefault,
  iv = STATIC_IV
) {
  const crypto = require('crypto')
  // Use the async `crypto.scrypt()` instead.
  const key = await scryptAsync(password, STATIC_SALT, KEY_BYTES)
  const decipher = crypto.createDecipheriv(algorithm, key, iv)
  // Encrypted using same algorithm, key and iv.
  let decrypted = decipher.update(encrypted, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  return decrypted
}
