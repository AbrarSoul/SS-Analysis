"""
Section 9 ground-truth test bundle: CASE-0216
(matrix-org/matrix-js-sdk, src/crypto/algorithms/megolm.ts
MegolmEncryption.reshareKeyWithDevice, CVE-2021-40823, CWE-290 authentication
bypass by spoofing).

Core vulnerable mechanism: when a device asks for a Megolm session key again,
`reshareKeyWithDevice` decides whether to re-send it from
`obSessionInfo.sharedWithDevices[userId][device.deviceId]`, which records only
the chain index sent to that (user id, DEVICE ID). It never records WHICH
device key that entry belonged to. A device id is just a string an account
holder chooses, so a malicious homeserver (or the account's other client) can
register a new device with the same device id but a different identity key and
receive the session key that was shared with the original device. The upstream
fix records the identity key next to the chain index (`SharedWithData`) and
refuses to re-share when `device.getIdentityKey()` differs.

Sibling sites: the identity key has to be recorded wherever a device is marked
as shared-with: `markSharedWithDevice` is called from the send path (after
sendToDevice succeeds) and from `notifyFailedOlmDevices`; the safe variant
records the key at both. `sharedWithTooManyDevices` and
`getDevicesWithoutSession`-style readers only test key presence and are
unaffected.

Verification: `markSharedWithDevice` and `reshareKeyWithDevice` are extracted
from each full file (type annotations stripped) into a Node script with a fake
olmDevice / baseApis / olmlib that record what would be sent. A session is
shared with device D (identity key K1), then D is "re-registered" with the same
id and identity key K2 and reshareKeyWithDevice is called for the new device.
The two markSharedWithDevice call sites inside the send path are covered by
`node --check`/type stripping only, since exercising them needs the full
class and a homeserver.

Every variant is the FULL real file. reshareKeyWithDevice is public API called
from the crypto module, so its name and signature are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0216"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
CHECK = '''        const sentChainIndex = obSessionInfo.sharedWithDevices[userId][device.deviceId];
        if (sentChainIndex === undefined) {'''
v1 = swap(original, CHECK, '''        const previousChainIndex = obSessionInfo.sharedWithDevices[userId][device.deviceId];
        if (previousChainIndex === undefined) {''')
v1 = swap(v1, "this.roomId, senderKey, sessionId, sentChainIndex,", "this.roomId, senderKey, sessionId, previousChainIndex,")
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CHECK, '''        const sentChainIndex = this.lookupSentChainIndex(obSessionInfo, userId, device.deviceId);
        if (sentChainIndex === undefined) {''')
v2 = swap(v2, "    public async reshareKeyWithDevice(", '''    private lookupSentChainIndex(
        info: OutboundSessionInfo,
        userId: string,
        deviceId: string,
    ): number | undefined {
        return info.sharedWithDevices[userId]?.[deviceId];
    }

    public async reshareKeyWithDevice(''')
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Keeps sharedWithDevices as chain indices and records identity keys in a
# parallel map (upstream turns the value into {deviceKey, messageIndex}).
v3 = swap(original, "    public sharedWithDevices: Record<string, Record<string, number>> = {};\n",
          "    public sharedWithDevices: Record<string, Record<string, number>> = {};\n"
          "    public sharedWithDeviceKeys: Record<string, Record<string, string>> = {};\n")
v3 = swap(v3, '''    public markSharedWithDevice(userId: string, deviceId: string, chainIndex: number): void {
        if (!this.sharedWithDevices[userId]) {
            this.sharedWithDevices[userId] = {};
        }
        this.sharedWithDevices[userId][deviceId] = chainIndex;''', '''    public markSharedWithDevice(userId: string, deviceId: string, chainIndex: number, deviceKey: string): void {
        if (!this.sharedWithDevices[userId]) {
            this.sharedWithDevices[userId] = {};
        }
        if (!this.sharedWithDeviceKeys[userId]) {
            this.sharedWithDeviceKeys[userId] = {};
        }
        this.sharedWithDevices[userId][deviceId] = chainIndex;
        this.sharedWithDeviceKeys[userId][deviceId] = deviceKey;''')
v3 = swap(v3, '''        const contentMap = {};

        const promises = [];
        for (let i = 0; i < userDeviceMap.length; i++) {''', '''        const contentMap = {};
        const identityKeys: Record<string, Record<string, string>> = {};

        const promises = [];
        for (let i = 0; i < userDeviceMap.length; i++) {''')
v3 = swap(v3, '''            if (!contentMap[userId]) {
                contentMap[userId] = {};
            }
            contentMap[userId][deviceId] = encryptedContent;
''', '''            if (!contentMap[userId]) {
                contentMap[userId] = {};
            }
            if (!identityKeys[userId]) {
                identityKeys[userId] = {};
            }
            identityKeys[userId][deviceId] = deviceInfo.getIdentityKey();
            contentMap[userId][deviceId] = encryptedContent;
''')
v3 = swap(v3, '''                        session.markSharedWithDevice(
                            userId, deviceId, chainIndex,
                        );''', '''                        session.markSharedWithDevice(
                            userId, deviceId, chainIndex, identityKeys[userId][deviceId],
                        );''')
v3 = swap(v3, '''            session.markSharedWithDevice(
                userId, deviceId, key.chain_index,
            );''', '''            session.markSharedWithDevice(
                userId, deviceId, key.chain_index, deviceInfo.getIdentityKey(),
            );''')
v3 = swap(v3, CHECK + '''
            logger.debug(
                "megolm session ID " + sessionId + " never shared with device " +
                userId + ":" + device.deviceId,
            );
            return;
        }
''', CHECK + '''
            logger.debug(
                "megolm session ID " + sessionId + " never shared with device " +
                userId + ":" + device.deviceId,
            );
            return;
        }

        const sharedKey = obSessionInfo.sharedWithDeviceKeys[userId]?.[device.deviceId];
        if (sharedKey !== device.getIdentityKey()) {
            logger.warn(
                `Session ${sessionId} was shared with ${userId}:${device.deviceId} under a different ` +
                `identity key (${sharedKey}, now ${device.getIdentityKey()}): not re-sharing`,
            );
            return;
        }
''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

BENIGN = '''// Standalone example of the same shape: a per-device "already synced" record
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
'''
(CASE_DIR / "benign_lookalike.ts").write_text(BENIGN)
