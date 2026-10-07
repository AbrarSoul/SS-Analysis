// Standalone example of the same shape: a per-device "already synced" record
// keyed by device id, where the pairing token is only a UI hint and nothing
// secret is sent based on it.
export class SyncLedger {
    private lastIndex: Record<string, number> = {};

    markSynced(deviceId: string, index: number): void {
        this.lastIndex[deviceId] = index;
    }

    needsResync(deviceId: string, currentIndex: number): boolean {
        const seen = this.lastIndex[deviceId];
        return seen === undefined || seen < currentIndex;
    }
}
