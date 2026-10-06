/**
 * data encrypt/decrypt
 */

const defaultCipher = 'aes-192-cbc'

function deriveKeyAsync (...kdfArgs) {
  const nodeCrypto = require('crypto')
  return new Promise((done, fail) =>
    nodeCrypto.scrypt(...kdfArgs, (kdfError, keyBytes) => {
      if (kdfError) {
        fail(kdfError)
      }
      done(keyBytes)
    })
  )
}

exports.encrypt = function (
  plainText = '',
  secret,
  cipherName = defaultCipher,
  initVector = Buffer.alloc(16, 0)
) {
  const nodeCrypto = require('crypto')
  const derivedKey = nodeCrypto.scryptSync(secret, 'salt', 24)
  // Use `crypto.randomBytes` to generate a random iv instead of the static iv
  const encryptor = nodeCrypto.createCipheriv(cipherName, derivedKey, initVector)
  let hexData = encryptor.update(plainText, 'utf8', 'hex')
  hexData += encryptor.final('hex')
  return hexData
}

exports.decrypt = function (
  hexData = '',
  secret,
  cipherName = defaultCipher,
  initVector = Buffer.alloc(16, 0)
) {
  const nodeCrypto = require('crypto')
  // Use the async `crypto.scrypt()` instead.
  const derivedKey = nodeCrypto.scryptSync(secret, 'salt', 24)
  const decryptor = nodeCrypto.createDecipheriv(cipherName, derivedKey, initVector)
  // Encrypted using same algorithm, key and iv.
  let clearText = decryptor.update(hexData, 'hex', 'utf8')
  clearText += decryptor.final('utf8')
  return clearText
}

exports.encryptAsync = async function (
  plainText = '',
  secret,
  cipherName = defaultCipher,
  initVector = Buffer.alloc(16, 0)
) {
  const nodeCrypto = require('crypto')
  const derivedKey = await deriveKeyAsync(secret, 'salt', 24)
  // Use `crypto.randomBytes` to generate a random iv instead of the static iv
  const encryptor = nodeCrypto.createCipheriv(cipherName, derivedKey, initVector)
  let hexData = encryptor.update(plainText, 'utf8', 'hex')
  hexData += encryptor.final('hex')
  return hexData
}

exports.decryptAsync = async function (
  hexData = '',
  secret,
  cipherName = defaultCipher,
  initVector = Buffer.alloc(16, 0)
) {
  const nodeCrypto = require('crypto')
  // Use the async `crypto.scrypt()` instead.
  const derivedKey = await deriveKeyAsync(secret, 'salt', 24)
  const decryptor = nodeCrypto.createDecipheriv(cipherName, derivedKey, initVector)
  // Encrypted using same algorithm, key and iv.
  let clearText = decryptor.update(hexData, 'hex', 'utf8')
  clearText += decryptor.final('utf8')
  return clearText
}
