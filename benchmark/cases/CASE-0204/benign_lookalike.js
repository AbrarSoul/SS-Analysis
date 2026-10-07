"use strict";

/**
 * Same "describe a page request for the log" step as the conversion
 * listener's debug line, but it only FORMATS text; it starts nothing, loads
 * nothing and never touches the browser, so it cannot read a local file.
 */
function describeRequest(r) {
  return `Page request: ${r.method()} (${r.resourceType()}) ${r.url()}`;
}

module.exports = describeRequest;
