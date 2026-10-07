"use strict";
let { validateEvent, verifyEvent, nip19 } = require("nostr-tools");
let { authorized_keys, private_keys, noscraper } = require(process.env.BOSTR_CONFIG_PATH || "./config");

authorized_keys = authorized_keys?.map(i => i.startsWith("npub") ? nip19.decode(i).data : i);

for (const key in private_keys) {
  if (!key.startsWith("npub")) continue;
  private_keys[nip19.decode(key).data] = private_keys[key];

  delete private_keys[key];
}

module.exports = (challengeToken, authEvent, socket, request) => {
  if (!authorized_keys?.length && !Object.keys(private_keys).length && !noscraper) return; // do nothing
  if (!validateEvent(authEvent) || !verifyEvent(authEvent)) {
    socket.send(JSON.stringify(["NOTICE", "error: invalid challenge response."]));
    return false;
  }

  if (!authorized_keys?.includes(authEvent.pubkey) && !private_keys[authEvent.pubkey] && !noscraper) {
    socket.send(JSON.stringify(["OK", authEvent.id, false, "unauthorized."]));
    return false;
  }

  if (authEvent.kind != 22242) {
    socket.send(JSON.stringify(["OK", authEvent.id, false, "not kind 22242."]));
    return false;
  }

  const eventTags = Object.fromEntries(authEvent.tags);

  if (!eventTags.relay?.includes(request.headers.host)) {
    socket.send(JSON.stringify(["OK", authEvent.id, false, "unmatched relay url."]));
    return false;
  };

  if (eventTags.challenge !== challengeToken) {
    socket.send(JSON.stringify(["OK", authEvent.id, false, "unmatched challenge string."]));
    return false;
  }

  socket.send(JSON.stringify(["OK", authEvent.id, true, `Hello ${authEvent.pubkey}`]));
  return true;
}
