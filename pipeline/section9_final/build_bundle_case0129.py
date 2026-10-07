"""
Section 9 ground-truth test bundle: CASE-0129
(bigbluebutton/bigbluebutton, bigbluebutton-html5 chat/service.js
isChatLocked, CVE-2020-27601, CWE-668 exposure of resource to wrong
sphere -- a broken access-control check).

Core vulnerable mechanism: `isChatLocked(receiverID)` decides whether a
locked viewer may chat. It reads the meeting with a MongoDB field projection
`{ fields: { 'lockSettingsProps.disablePublicChat': 1 } }` but LATER reads
`meeting.lockSettingsProps.disablePrivateChat`, which the projection
excluded, so the value is always undefined and private chat is never
treated as locked: a moderator's "lock private chat" setting is silently
ineffective and locked viewers can still send private messages. The upstream
fix adds `'lockSettingsProps.disablePrivateChat': 1` to the projection.

Every variant is the FULL real file with isChatLocked replaced. It is a
`const` arrow function exported by shorthand (`isChatLocked,`), so the
renamed variant renames the local binding and keeps the exported property
name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0129"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

HDR = "const isChatLocked = (receiverID) => {\n"
s = original.index(HDR)
e = original.index("\n};\n", s) + len("\n};\n")
BLOCK = original[s:e]
EXPORT = "  isChatLocked,\n"
PROJ = "    { fields: { 'lockSettingsProps.disablePublicChat': 1 } });\n"
assert original.count(HDR) == 1 and original.count(EXPORT) == 1 and BLOCK.count(PROJ) == 1
assert original.count("isChatLocked") == 2


def build(new_block, new_export=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    if new_export:
        assert out.count(EXPORT) == 1
        out = out.replace(EXPORT, new_export)
    return out


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        parts = re.split(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])(?!\s*:)" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename_outside_strings(BLOCK, (("isChatLocked", "chatIsRestricted"), ("receiverID", "peerId"), ("isPublic", "publicChat"),
                                   ("meeting", "meetingDoc"), ("user", "currentUser"), ("receiver", "peer"),
                                   ("isReceiverModerator", "peerIsModerator")))
assert "const chatIsRestricted = (peerId) => {" in b and "peerIsModerator" in b
assert "meetingDoc.lockSettingsProps.disablePrivateChat" in b and "currentUser.locked" in b
assert "'lockSettingsProps.disablePublicChat': 1" in b and "userId: Auth.userID" in b
(CASE_DIR / "variant_vulnerable_01.js").write_text(build(b, "  isChatLocked: chatIsRestricted,\n"))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(
    "  const meeting = Meetings.findOne({ meetingId: Auth.meetingID },\n" + PROJ,
    "  const meetingFields = { 'lockSettingsProps.disablePublicChat': 1 };\n"
    "  const meeting = Meetings.findOne({ meetingId: Auth.meetingID }, { fields: meetingFields });\n")
assert b != BLOCK and "meetingFields" in b
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Project the WHOLE lockSettingsProps subtree, so every lock setting the
# function reads is present (upstream adds the single missing dotted path).
b = BLOCK.replace(PROJ, "    { fields: { lockSettingsProps: 1 } });\n")
assert b != BLOCK
safe_source = build(b)
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import Meetings from '/imports/api/meetings';
import Auth from '/imports/ui/services/auth';

/**
 * Same "findOne with a field projection, then read a nested lock setting"
 * shape, but the projection includes EVERY field the function goes on to
 * read (disableRecording), so the check sees the real setting.
 */
export const isRecordingLocked = () => {
  const meeting = Meetings.findOne({ meetingId: Auth.meetingID },
    { fields: { 'lockSettingsProps.disableRecording': 1 } });

  return !!(meeting
    && meeting.lockSettingsProps
    && meeting.lockSettingsProps.disableRecording);
};
'''
assert "disableRecording': 1" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0129.")
