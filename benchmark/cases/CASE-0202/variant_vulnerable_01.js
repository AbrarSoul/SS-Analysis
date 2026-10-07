/*!
 * assign-deep <https://github.com/jonschlinkert/assign-deep>
 *
 * Copyright (c) 2017, Jon Schlinkert.
 * Released under the MIT License.
 */

'use strict';

var isPrimitive = require('is-primitive');
var assignSymbols = require('assign-symbols');
var typeOf = require('kind-of');

function assign(target/*, objects*/) {
  target = target || {};
  var len = arguments.length, i = 0;
  if (len === 1) {
    return target;
  }
  while (++i < len) {
    var val = arguments[i];
    if (isPrimitive(target)) {
      target = val;
    }
    if (isObject(val)) {
      mergeInto(target, val);
    }
  }
  return target;
}

/**
 * Shallow extend
 */

function mergeInto(dest, source) {
  assignSymbols(dest, source);

  for (var prop in source) {
    if (hasOwn(source, prop)) {
      var value = source[prop];
      if (isObject(value)) {
        if (typeOf(dest[prop]) === 'undefined' && typeOf(value) === 'function') {
          dest[prop] = value;
        }
        dest[prop] = assign(dest[prop] || {}, value);
      } else {
        dest[prop] = value;
      }
    }
  }
  return dest;
}

/**
 * Returns true if the object is a plain object or a function.
 */

function isObject(obj) {
  return typeOf(obj) === 'object' || typeOf(obj) === 'function';
}

/**
 * Returns true if the given `key` is an own property of `obj`.
 */

function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/**
 * Expose `assign`
 */

module.exports = assign;
