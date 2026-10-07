"""
Section 9 ground-truth test bundle: CASE-0098
(ant-media/ant-media-server, CVE-2024-35371 -- advisory CWE-125, but the
real defect fixed is CWE-117 log injection).

Core vulnerable mechanism: `deleteBroadcasts()` (and its twin
`deleteVoDs()`) log a caller-supplied stream/VoD id verbatim in
`logger.warn("... {} ...", id)`. An id containing CR/LF (e.g.
`x\\r\\n2024-01-01 ERROR forged entry`) forges log lines. The upstream
fix rewrites CR/LF in `id` to '_' before logging. (The other two hunks of
the fix -- startRecord, playNextItem -- were already sanitized and only
swap a literal for a constant; this case was hand-retargeted to
deleteBroadcasts, see benchmark/hand_curations.json.)

Every variant is the FULL real file with deleteBroadcasts replaced. The
safe variant ALSO fixes the sibling deleteVoDs, otherwise a file labeled
"safe" would still contain a real, unfixed log injection.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0098"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def method_block(src, header):
    s = src.index(header)
    e = src.index("\n\t}\n", s) + len("\n\t}\n")
    return src[s:e]


B_HDR = "\tprotected Result deleteBroadcasts(String[] streamIds) {"
V_HDR = "\tprotected Result deleteVoDs(String[] vodIds)\n"
assert original.count(B_HDR) == 1 and original.count(V_HDR) == 1
BLOCK_B = method_block(original, B_HDR)
BLOCK_V = method_block(original, V_HDR)
B_MARK = 'logger.warn("It cannot delete {} and breaking the loop", id);'
V_MARK = 'logger.warn("VoD:{} cannot be deleted and breaking the loop", id);'
assert BLOCK_B.count(B_MARK) == 1 and BLOCK_V.count(V_MARK) == 1
assert "toLogSafeToken" not in original


def build(replacements):
    out = original
    for old, new in replacements:
        assert new != old and out.count(old) == 1
        out = out.replace(old, new)
    return out


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK_B.replace("deleteBroadcasts", "removeStreamsByIds")
for old, new in (("streamIds", "ids"), ("id", "streamId"), ("result", "outcome")):
    b = re.sub(r"\b%s\b" % old, new, b)
assert 'logger.warn("It cannot delete {} and breaking the loop", streamId);' in b
assert "deleteBroadcasts" not in b and "deleteBroadcast(streamId)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build([(BLOCK_B, b)]))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK_B.replace(
    "\t\t\tfor (String id : streamIds)\n\t\t\t{\n\t\t\t\tresult = deleteBroadcast(id);\n",
    "\t\t\tfor (int i = 0; i < streamIds.length; i++)\n\t\t\t{\n\t\t\t\tString id = streamIds[i];\n\t\t\t\tresult = deleteBroadcast(id);\n")
assert b != BLOCK_B and B_MARK in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build([(BLOCK_B, b)]))

# --- Variant 3: transformed safe variant ---
# Allow-list sanitizer (anything outside [A-Za-z0-9._-] becomes '_', capped at
# 64 chars) applied to BOTH sibling methods, instead of upstream's
# blacklist of CR/LF on `id`.
HELPER = '''\tprivate static String toLogSafeToken(String value) {
\t\tif (value == null) {
\t\t\treturn "null";
\t\t}
\t\tString cleaned = value.replaceAll("[^A-Za-z0-9._-]", "_");
\t\treturn cleaned.length() > 64 ? cleaned.substring(0, 64) : cleaned;
\t}

'''
sb = BLOCK_B.replace(B_MARK, 'logger.warn("It cannot delete {} and breaking the loop", toLogSafeToken(id));')
sv = BLOCK_V.replace(V_MARK, 'logger.warn("VoD:{} cannot be deleted and breaking the loop", toLogSafeToken(id));')
safe_source = build([(BLOCK_B, HELPER + sb), (BLOCK_V, sv)])
assert B_MARK not in safe_source and V_MARK not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TicketPurger {

    private static final Logger logger = LoggerFactory.getLogger(TicketPurger.class);

    /**
     * Same loop-and-log-on-failure shape as a bulk delete, but each raw id is
     * parsed to a long BEFORE it is used or logged. Long.parseLong rejects
     * anything except an optional sign and digits (NumberFormatException), so
     * the value that reaches the logger can never contain CR/LF.
     */
    public boolean purgeTickets(String[] ticketIds) {
        boolean ok = true;
        if (ticketIds != null) {
            for (String raw : ticketIds) {
                long id = Long.parseLong(raw.trim());
                ok = purgeTicket(id);
                if (!ok) {
                    logger.warn("It cannot delete {} and breaking the loop", id);
                    break;
                }
            }
        }
        return ok;
    }

    private boolean purgeTicket(long id) {
        return id > 0;
    }
}
'''
assert "Long.parseLong" in benign_source  # logged value is numeric by construction
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0098.")
