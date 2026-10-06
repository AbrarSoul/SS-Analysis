import type { IncomingMessage } from 'http';
import type internal from 'stream';
import WebSocket, { WebSocketServer } from 'ws';

export class EchoController {
	server = new WebSocketServer({ noServer: true });

	/**
	 * Same handleUpgrade(request, socket, head, async (ws) => {...}) shape as
	 * the real controller, but the very first thing the callback does is
	 * attach an 'error' listener, so a malformed frame cannot become an
	 * unhandled 'error' event.
	 */
	handleUpgrade(request: IncomingMessage, socket: internal.Duplex, head: Buffer) {
		this.server.handleUpgrade(request, socket, head, async (ws) => {
			ws.on('error', () => ws.terminate());
			ws.on('message', (data: WebSocket.RawData) => ws.send(data));
		});
	}
}
