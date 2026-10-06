// 30-byte values encode to exactly 40 base64 characters with NO '=' padding.
const NONCE_BYTES = 30
const NONCE_BASE64_LENGTH = 40

/**
 * Same "concatenate two base64 strings, then decode once" pattern as the
 * handshake code, but it is only ever applied to fixed-length, padding-free
 * values (and refuses anything else), so decoding the concatenation is
 * byte-for-byte identical to decoding each value and joining the bytes: no
 * input is dropped.
 */
export function joinFixedLengthNonces (first: string, second: string): number[] {
  for (const value of [first, second]) {
    if (value.length !== NONCE_BASE64_LENGTH || value.includes('=')) {
      throw new Error('Nonce must be exactly ' + NONCE_BYTES + ' bytes of unpadded base64')
    }
  }
  return Array.from(Buffer.from(first + second, 'base64'))
}
