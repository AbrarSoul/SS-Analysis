"""
Section 9 ground-truth test bundle: CASE-0215
(matrix-org/matrix-appservice-irc, src/bridge/MatrixHandler.ts _onMemberEvent,
CVE-2024-39691, CWE-280 / CWE-755).

Core vulnerable mechanism: when a Matrix user joins a room, `_onMemberEvent`
records their join time as `event.origin_server_ts ?? Date.now()`, i.e. a
timestamp supplied by the (possibly malicious) sender's homeserver. Later,
when that user replies to an event, the bridge quotes the replied-to message
into IRC unless `senderJoinTs > cachedEvent.timestamp` ("the user joined AFTER
the event was sent"). A homeserver that backdates the join event's
origin_server_ts makes the recorded join time earlier than any cached
message, so a user who joined late can reply to (and thereby have quoted into
IRC) messages from before they joined. The upstream fix records `Date.now()`
(the bridge's own clock at receipt).

Measured caveat, kept in the manifest notes: `cachedEvent.timestamp` for the
replied-to event is also filled from `event.origin_server_ts`
(the `timestamp: event.origin_server_ts` cache write in _onMessage), which the
upstream fix does not change; the comparison is therefore between a bridge-clock
join time and a sender-supplied message time.

Sibling sites: memberJoinTs is written only in _onMemberEvent and read only in
the reply check.

Verification: `_onMemberEvent` is extracted verbatim from each full file (type
annotations stripped) into a small class holding the real `memberJoinTs`
semantics (a Map standing in for QuickLRU) and the reply-guard comparison copied
from the class (`senderJoinTs > cachedEvent.timestamp`), with Date.now frozen.
A join event whose origin_server_ts is backdated 1,000,000 ms is processed,
then a reply to an event cached 500,000 ms before "now" is checked.

Every variant is the FULL real file. _onMemberEvent is a private method called
from event handlers, so its name stays; the renamed variant only introduces a local for the
map key (the parameters keep their names).
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0215"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original

s = original.index("    private _onMemberEvent(req: BridgeRequest, event: OnMemberEventData) {")
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
assert original.count(BLOCK) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


V1 = '''    private _onMemberEvent(req: BridgeRequest, event: OnMemberEventData) {
        const joinKey = `${event.room_id}/${event.state_key}`;
        if (event.content.membership === 'join') {
            this.memberJoinTs.set(joinKey, event.origin_server_ts ?? Date.now());
        }
        else {
            this.memberJoinTs.delete(joinKey);
        }
        this.memberTracker?.onEvent(event);
    }
'''
(CASE_DIR / "variant_vulnerable_01.ts").write_text(build(V1))

V2 = '''    private _onMemberEvent(req: BridgeRequest, event: OnMemberEventData) {
        const isJoin = event.content.membership === 'join';
        const claimedTs = event.origin_server_ts ?? Date.now();
        if (isJoin) {
            this.memberJoinTs.set(`${event.room_id}/${event.state_key}`, claimedTs);
        }
        else {
            this.memberJoinTs.delete(`${event.room_id}/${event.state_key}`);
        }
        this.memberTracker?.onEvent(event);
    }
'''
(CASE_DIR / "variant_vulnerable_02.ts").write_text(build(V2))

V3 = '''    private _onMemberEvent(req: BridgeRequest, event: OnMemberEventData) {
        const memberKey = `${event.room_id}/${event.state_key}`;
        if (event.content.membership === 'join') {
            // Use the bridge's own clock: origin_server_ts is chosen by the sender's homeserver.
            const receivedAt = Date.now();
            this.memberJoinTs.set(memberKey, receivedAt);
        }
        else {
            this.memberJoinTs.delete(memberKey);
        }
        this.memberTracker?.onEvent(event);
    }
'''
(CASE_DIR / "variant_safe_01.ts").write_text(build(V3))

BENIGN = '''// Standalone example of the same shape: remembering when a client was last
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
'''
(CASE_DIR / "benign_lookalike.ts").write_text(BENIGN)
