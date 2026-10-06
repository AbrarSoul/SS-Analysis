"use strict";

/**
 * Same "read a length prefix" shape as getLength, but it accepts only the
 * MINIMAL encoding: a long-form length must use the fewest octets and must be
 * larger than the short form can express, and at most 4 octets are read with
 * unsigned arithmetic, so one value has exactly one valid encoding.
 */
function readMinimalLength(bytes, pos) {
  var first = bytes[pos.place++];
  if (!(first & 0x80)) {
    return first;
  }
  var octets = first & 0x7f;
  if (octets === 0 || octets > 4) {
    return -1;
  }
  var value = 0;
  for (var i = 0; i < octets; i++) {
    value = ((value << 8) | bytes[pos.place++]) >>> 0;
  }
  if (value <= 0x7f || (octets > 1 && bytes[pos.place - octets] === 0)) {
    return -1;
  }
  return value;
}

module.exports = readMinimalLength;
