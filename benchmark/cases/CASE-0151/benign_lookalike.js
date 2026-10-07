"use strict";
const crypto = require("crypto");

// A zero nonce is only safe when the key is NEVER reused; here every message
// gets its own random 256-bit key, so the (key, nonce) pair is unique.
const ZERO_NONCE = Buffer.alloc(12, 0);

/**
 * Same createCipheriv + fixed-IV shape as a static-IV cipher, but the key is
 * fresh and random per message and GCM authenticates the data. Returns the
 * one-time key (to be delivered out of band) and the sealed message.
 */
function sealWithOneTimeKey(plainText) {
  const key = crypto.randomBytes(32);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, ZERO_NONCE);
  const body = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  return { key: key, sealed: Buffer.concat([cipher.getAuthTag(), body]) };
}

module.exports = { sealWithOneTimeKey: sealWithOneTimeKey };
