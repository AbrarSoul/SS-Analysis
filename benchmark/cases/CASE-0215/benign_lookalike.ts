// Standalone example of the same shape: remembering when a client was last
// seen, stamped with the local clock, for an idle-timeout that only decides
// when to close a connection.
export class IdleTracker {
    private lastSeen = new Map<string, number>();

    onActivity(clientId: string, remoteTs?: number): void {
        void remoteTs; // remote clocks are ignored on purpose
        this.lastSeen.set(clientId, Date.now());
    }

    isIdle(clientId: string, limitMs: number): boolean {
        const seen = this.lastSeen.get(clientId);
        return seen === undefined || Date.now() - seen > limitMs;
    }
}
