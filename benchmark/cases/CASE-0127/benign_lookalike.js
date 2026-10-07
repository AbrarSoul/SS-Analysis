"use strict";

function isPrimitiveHeaderValue(value) {
  var kind = typeof value;
  return kind === "string" || kind === "number" || kind === "boolean";
}

/**
 * Same "if it is not a string, coerce with ''+value+''" idiom as a header
 * normaliser, but only values that are ALREADY string/number/boolean ever
 * reach the coercion (everything else is filtered out first), and
 * concatenating a primitive with '' can never throw.
 */
function normalizeHeaders(headers) {
  var result = {};
  Object.keys(headers).forEach(function (name) {
    var value = headers[name];
    if (!isPrimitiveHeaderValue(value)) {
      return;
    }
    if (typeof value !== "string") {
      value = "" + value + "";
    }
    result[name] = value;
  });
  return result;
}

module.exports = { normalizeHeaders: normalizeHeaders };
