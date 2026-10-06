"use strict";
const seenPubkeys = new Set();
const pubkeyCache = Object.create(null);

// Same `!a.includes(x) && !b[x] && !flag` shape, but the result only
// decides whether a debug log line is printed. No access-control
// decision depends on it.
function shouldSkipDebugLog(watchedKeys, pubkey, verbose) {
  return !watchedKeys?.includes(pubkey) && !pubkeyCache[pubkey] && !verbose;
}

module.exports = (watchedKeys, pubkey, verbose) => {
  if (shouldSkipDebugLog(watchedKeys, pubkey, verbose)) return;
  seenPubkeys.add(pubkey);
  console.debug("watching pubkey", pubkey);
};
