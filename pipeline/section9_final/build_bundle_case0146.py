"""
Section 9 ground-truth test bundle: CASE-0146
(directus/directus, api/src/websocket/controllers/base.ts SocketController
handleUpgrade / handleStrictUpgrade / handleHandshakeUpgrade,
CVE-2023-45820, CWE-248 uncaught exception -> denial of service).

Located target: `this.server.handleUpgrade(request, socket, head, async (ws) => {`
(three identical call sites in this class).

Core vulnerable mechanism: after `this.server.handleUpgrade(...)` the new
`ws` has NO 'error' listener until `createClient()` attaches one (only after
the 'connection' event). In handshake auth mode the connection is held back
until an auth message arrives, and `waitForAnyMessage` only listens for
'message', so a client that sends an invalid WebSocket frame before
authenticating makes the ws Receiver emit 'error' on a listener-less
emitter: an unhandled 'error' event that crashes the whole API process.
Measured by running the real class (esbuild-stripped, with the real ws
8.14.1 and a copy of the real waitForAnyMessage): handshake mode + an RSV1
frame -> "Unhandled 'error' event" crash; strict and public modes survive
(createClient attaches the error listener at once). The upstream fix adds
`catchInvalidMessages(ws)` (a `data` listener workaround plus an error
listener) at all three upgrade sites.

Sibling sites: the safe variant guards ALL THREE upgrade callbacks, and the
vulnerable variants leave all three unguarded.

Every variant is the FULL real file. handleUpgrade is bound by name in the
constructor and may be overridden, so the renamed variant renames the
locals inside the three upgrade callbacks, not the methods.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0146"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original

A = '''		this.server.handleUpgrade(request, socket, head, async (ws) => {
			const state = { accountability: null, expires_at: null } as AuthenticationState;
			this.server.emit('connection', ws, state);
		});
'''
B = '''		this.server.handleUpgrade(request, socket, head, async (ws) => {
			const state = { accountability, expires_at } as AuthenticationState;
			this.server.emit('connection', ws, state);
		});
'''
C_HEAD = '''		this.server.handleUpgrade(request, socket, head, async (ws) => {
			try {
				const payload = await waitForAnyMessage(ws, this.authentication.timeout);
'''
C_BODY_OLD = '''				const state = await authenticateConnection(WebSocketAuthMessage.parse(payload));
				ws.send(authenticationSuccess(payload['uid'], state.refresh_token));
				this.server.emit('connection', ws, state);
			} catch {
				logger.debug('WebSocket authentication handshake failed');
				const error = new WebSocketError('auth', 'AUTH_FAILED', 'Authentication handshake failed.');
				handleWebSocketError(ws, error, 'auth');
				ws.close();
			}
'''
CREATE_CLIENT = "\tcreateClient(ws: WebSocket, { accountability, expires_at }: AuthenticationState) {\n"
for x in (A, B, C_HEAD, C_BODY_OLD, CREATE_CLIENT):
    assert original.count(x) == 1, x


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, A, '''		this.server.handleUpgrade(request, socket, head, async (conn) => {
			const initialState = { accountability: null, expires_at: null } as AuthenticationState;
			this.server.emit('connection', conn, initialState);
		});
''')
v1 = swap(v1, B, '''		this.server.handleUpgrade(request, socket, head, async (conn) => {
			const authState = { accountability, expires_at } as AuthenticationState;
			this.server.emit('connection', conn, authState);
		});
''')
v1 = swap(v1, C_HEAD, '''		this.server.handleUpgrade(request, socket, head, async (conn) => {
			try {
				const firstMessage = await waitForAnyMessage(conn, this.authentication.timeout);
''')
v1 = swap(v1, C_BODY_OLD, '''				const authResult = await authenticateConnection(WebSocketAuthMessage.parse(firstMessage));
				conn.send(authenticationSuccess(firstMessage['uid'], authResult.refresh_token));
				this.server.emit('connection', conn, authResult);
			} catch {
				logger.debug('WebSocket authentication handshake failed');
				const error = new WebSocketError('auth', 'AUTH_FAILED', 'Authentication handshake failed.');
				handleWebSocketError(conn, error, 'auth');
				conn.close();
			}
''')
v1 = swap(v1, "getMessageType(payload) !== 'auth'", "getMessageType(firstMessage) !== 'auth'")
assert "payload" not in v1.split("handleHandshakeUpgrade")[1].split("createClient")[0]
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, A, '''		this.server.handleUpgrade(request, socket, head, async (ws) => {
			this.acceptConnection(ws, { accountability: null, expires_at: null } as AuthenticationState);
		});
''')
v2 = swap(v2, B, '''		this.server.handleUpgrade(request, socket, head, async (ws) => {
			this.acceptConnection(ws, { accountability, expires_at } as AuthenticationState);
		});
''')
v2 = swap(v2, "\t\t\t\tthis.server.emit('connection', ws, state);\n\t\t\t} catch {", "\t\t\t\tthis.acceptConnection(ws, state);\n\t\t\t} catch {")
v2 = swap(v2, CREATE_CLIENT, '''\tprivate acceptConnection(ws: WebSocket, state: AuthenticationState) {
\t\tthis.server.emit('connection', ws, state);
\t}

''' + CREATE_CLIENT)
assert v2.count("this.acceptConnection(") == 3
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant ---
# An 'error' listener is attached as the FIRST statement of every upgrade
# callback (through a small helper), so an invalid frame can never reach a
# listener-less emitter. Upstream's catchInvalidMessages also prepends a
# 'data' listener workaround for ws issue 2098; this variant relies on the
# error listener alone (measured sufficient on ws 8.14.1 for RSV1, bad
# opcode, invalid UTF-8, bad close code, oversized length, fragmented control
# and unmasked frames).
v3 = swap(original, A, A.replace("async (ws) => {\n", "async (ws) => {\n\t\t\tthis.guardConnection(ws);\n"))
v3 = swap(v3, B, B.replace("async (ws) => {\n", "async (ws) => {\n\t\t\tthis.guardConnection(ws);\n"))
v3 = swap(v3, C_HEAD, C_HEAD.replace("async (ws) => {\n", "async (ws) => {\n\t\t\tthis.guardConnection(ws);\n\n"))
v3 = swap(v3, CREATE_CLIENT, '''\tprivate guardConnection(ws: WebSocket) {
\t\t// keeps a malformed frame from surfacing as an unhandled 'error' event
\t\tws.on('error', (error) => {
\t\t\tif (error.message) logger.debug(error.message);
\t\t});
\t}

''' + CREATE_CLIENT)
assert v3.count("this.guardConnection(ws);") == 3
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import type { IncomingMessage } from 'http';
import type internal from 'stream';
import WebSocket, { WebSocketServer } from 'ws';

export class EchoController {
\tserver = new WebSocketServer({ noServer: true });

\t/**
\t * Same handleUpgrade(request, socket, head, async (ws) => {...}) shape as
\t * the real controller, but the very first thing the callback does is
\t * attach an 'error' listener, so a malformed frame cannot become an
\t * unhandled 'error' event.
\t */
\thandleUpgrade(request: IncomingMessage, socket: internal.Duplex, head: Buffer) {
\t\tthis.server.handleUpgrade(request, socket, head, async (ws) => {
\t\t\tws.on('error', () => ws.terminate());
\t\t\tws.on('message', (data: WebSocket.RawData) => ws.send(data));
\t\t});
\t}
}
'''
assert "ws.on('error'" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)
print("Wrote 4 new samples for CASE-0146.")
