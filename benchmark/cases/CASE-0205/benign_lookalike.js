"use strict";

/**
 * Same Math.random() based byte generator shape as the weak seed fallback,
 * but it is used only for retry JITTER (a delay in milliseconds), a value with
 * no security meaning, so predictability costs nothing.
 */
function jitterMs(baseMs) {
  return baseMs + Math.floor(Math.random() * baseMs);
}

module.exports = jitterMs;
