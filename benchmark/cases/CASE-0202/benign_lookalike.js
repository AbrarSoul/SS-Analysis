"use strict";

/**
 * Same "copy own keys, recursing into nested objects" loop as the deep
 * assign, but the destination and every nested container are created with
 * Object.create(null), so there is no prototype chain to pollute.
 */
function copyInto(target, source) {
  Object.keys(source).forEach(function (key) {
    var value = source[key];
    if (value !== null && typeof value === "object") {
      target[key] = copyInto(Object.create(null), value);
    } else {
      target[key] = value;
    }
  });
  return target;
}

module.exports = function (source) { return copyInto(Object.create(null), source); };
