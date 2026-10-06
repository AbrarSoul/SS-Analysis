"use strict";

// The only origins that may open a WebSocket, exact keys of a plain lookup table.
var ALLOWED_ORIGINS = { "https://app.example.com": true, "https://admin.example.com": true };

/**
 * Same "echo the client's Origin into the 101 handshake response" shape as a
 * WebSocket upgrade handler, but the value written is one of the fixed,
 * developer-defined keys above (looked up by own-property test), never
 * arbitrary request text, so it cannot carry CR/LF and cannot be forged.
 */
function acceptUpgrade(request, socket) {
  var origin = request.headers.origin;
  if (!Object.prototype.hasOwnProperty.call(ALLOWED_ORIGINS, origin)) {
    socket.write("HTTP/1.1 403 Origin not allowed\r\n\r\n");
    socket.destroy();
    return false;
  }
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      "Sec-WebSocket-Origin: " +
      origin +
      "\r\n\r\n",
  );
  return true;
}

module.exports = { acceptUpgrade: acceptUpgrade };
