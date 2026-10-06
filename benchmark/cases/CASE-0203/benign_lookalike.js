"use strict";

/**
 * Same "look a name up in a values object" step as the expression evaluator,
 * but the lookup is restricted to OWN properties and returns undefined for
 * anything inherited, so it cannot expose Object.prototype members.
 */
function lookup(values, name) {
  return Object.prototype.hasOwnProperty.call(values, name) ? values[name] : undefined;
}

module.exports = lookup;
