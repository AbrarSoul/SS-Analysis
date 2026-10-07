"""
Section 9 ground-truth test bundle: CASE-0010
(projectdiscovery/interactsh, CVE-2024-5262, CWE-552 -- files/directories
accessible to external parties).

Core vulnerable mechanism: impacket's smbserver.SimpleSMBServer
auto-creates dangerous default administrative shares (IPC$, ADMIN$, C$,
PRINT$, FAX$, NETLOGON, SYSVOL) on construction. This script instantiates
it, binds it to 0.0.0.0, and calls .start() without ever removing those
default shares -- so anonymous SMB clients get full access to C$ (the
whole filesystem), not just the intended "interactsh" share. The
vulnerability is an OMISSION (missing removeShare() calls), not a single
dangerous call.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0010"
original = (CASE_DIR / "vulnerable_source.py").read_text()

assert original == (
    'import sys\n'
    'from impacket import smbserver\n'
    '\n'
    'log_filename = "log.txt"\n'
    'if len(sys.argv) >= 2:\n'
    '    log_filename = sys.argv[1]\n'
    'port = 445\n'
    'if len(sys.argv) >= 3:\n'
    '    port = int(sys.argv[2])\n'
    '\n'
    'server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=port)\n'
    'server.setSMB2Support(True)\n'
    'server.addShare("interactsh", "/interactsh")\n'
    "server.setSMBChallenge('')\n"
    'server.setLogFile(log_filename)\n'
    'server.start()\n'
), "vulnerable_source.py content drifted from expected -- aborting rather than guess"

# --- Variant 1: renamed vulnerable variant ---
# Rename the standalone identifier server -> smb_server throughout the
# script (all 6 references), via a word-boundary regex so the embedded
# "server" substring inside the imported module name `smbserver` is left
# untouched. Same exact vulnerability: still no removeShare() calls
# anywhere.
renamed_source = re.sub(r"\bserver\b", "smb_server", original)
assert "from impacket import smbserver\n" in renamed_source
assert "smb_server = smbserver.SimpleSMBServer" in renamed_source
assert "smb_server.addShare(\"interactsh\", \"/interactsh\")" in renamed_source
assert "smb_server.start()" in renamed_source
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variables for the share
# name/path. Same exact vulnerability (still missing removeShare() calls
# for the dangerous default shares), no renaming.
structural_source = original.replace(
    'server.addShare("interactsh", "/interactsh")\n',
    'share_name = "interactsh"\n'
    'share_path = "/interactsh"\n'
    'server.addShare(share_name, share_path)\n',
)
assert structural_source != original
assert 'share_name = "interactsh"' in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (dangerous default shares removed
# before the server starts) but implemented inline with a module-level
# tuple constant and a for-loop, instead of the real patch's separate
# configure_shares() helper function -- materially different structure,
# not byte-identical to the known fix.
safe_source = original.replace(
    'server.addShare("interactsh", "/interactsh")\n',
    'DANGEROUS_DEFAULT_SHARES = ("IPC$", "ADMIN$", "C$", "PRINT$", "FAX$", "NETLOGON", "SYSVOL")\n'
    'for dangerous_share in DANGEROUS_DEFAULT_SHARES:\n'
    '    server.removeShare(dangerous_share)\n'
    'server.addShare("interactsh", "/interactsh")\n',
)
assert safe_source != original
assert "server.removeShare(dangerous_share)" in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Appends a small local class
# whose usage superficially matches the vulnerable shape (.addShare(...)
# followed by .start(), no removeShare() calls) but is genuinely safe: it
# is a no-op stand-in class, never smbserver.SimpleSMBServer, so it never
# binds a network socket or exposes any real filesystem path.
BENIGN_ADDITION = '''

class MockShareServer:
    """A no-op stand-in for tests.

    Does not bind to any network socket or expose any real filesystem
    path, unlike smbserver.SimpleSMBServer -- so calling addShare()/
    start() on it with no removeShare() calls carries no risk.
    """

    def addShare(self, name, path):
        pass

    def start(self):
        pass


test_server = MockShareServer()
test_server.addShare("interactsh", "/interactsh")
test_server.start()
'''
benign_source = safe_source + BENIGN_ADDITION
assert benign_source != safe_source
assert "MockShareServer" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)

print("Wrote 4 new samples for CASE-0010.")
