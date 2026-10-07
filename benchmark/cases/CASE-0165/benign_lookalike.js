"use strict";

const KNOWN_KEYS = ["page", "size"];

/**
 * Same "split the path into key/value pairs" shape as getUrlParams, but only
 * two exact, developer-defined keys are ever read, and the values are coerced
 * to bounded integers, so the case of an unknown segment cannot hide or
 * select any protected object.
 */
function parsePaging(pathname) {
  const parts = pathname.split("/").slice(1);
  const out = { page: 1, size: 20 };
  for (let a = 0; a + 1 < parts.length; a += 2) {
    if (KNOWN_KEYS.indexOf(parts[a]) !== -1) {
      const n = parseInt(parts[a + 1], 10);
      if (n > 0 && n <= 100) {
        out[parts[a]] = n;
      }
    }
  }
  return out;
}

module.exports = { parsePaging: parsePaging };
