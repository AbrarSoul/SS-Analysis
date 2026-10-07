"use strict";

/**
 * Same "if the target host equals our own host, navigate directly" shortcut,
 * but it is only taken for http(s) URLs whose scheme has been validated FIRST,
 * so a javascript:, data: or blob: URL that merely carries our host name in
 * its authority can never reach the shortcut.
 */
function canNavigateDirectly(target, ownHost) {
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return false;
  }
  return target.host === ownHost.host;
}

module.exports = { canNavigateDirectly: canNavigateDirectly };
