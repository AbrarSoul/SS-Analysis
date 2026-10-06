"""
Section 9 ground-truth test bundle: CASE-0043
(9001/copyparty, CVE-2025-58753, CWE-552/CWE-862).

Core vulnerable mechanism: VFS.canonical() resolves a share's realpath with
no awareness of `shr_files` (the allow-listed filename subset for a
file-restricted share). The real fix is a cross-cutting change (rename
canonical/dcanonical to _canonical/_dcanonical, add restricted
_canonical_shr/_dcanonical_shr variants, wire share nodes to the restricted
variants) -- Step 5's auto-locator (after this session's bug fixes) settled
on the single most representative vulnerable/patched pair: the original
unrestricted canonical() as "vulnerable", and the new restricted
_canonical_shr() as "patched". This bundle builds variants around exactly
that pair, since that is what the model actually sees as context.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0043"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    def canonical(self, rem: str, resolve: bool = True) -> str:
        """returns the canonical path (fully-resolved absolute fs path)"""
        ap = self.realpath
        if rem:
            ap += "/" + rem

        return absreal(ap) if resolve else ap'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename canonical -> resolve_path, rem -> relative, ap -> abs_path. Same
# exact missing-shr_files-check sink. Renamed only at this method's own
# definition and body -- NOT at other call sites in the file (canonical()
# is called elsewhere, e.g. AuthSrv.setup ~line 2759, and blindly renaming
# every occurrence would go beyond this bundle's scope and risk producing
# a file that no longer parses coherently as "the same program, one method
# renamed").
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def resolve_path(self, relative: str, resolve: bool = True) -> str:
        """returns the canonical path (fully-resolved absolute fs path)"""
        abs_path = self.realpath
        if relative:
            abs_path += "/" + relative

        return absreal(abs_path) if resolve else abs_path''',
)
assert "def resolve_path(self, relative: str" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting.
# Same exact vulnerability (no shr_files check anywhere), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def canonical(self, rem: str, resolve: bool = True) -> str:
        """returns the canonical path (fully-resolved absolute fs path)"""
        ap = self.realpath
        if rem:
            ap = ap + "/" + rem

        if not resolve:
            return ap
        resolved_path = absreal(ap)
        return resolved_path''',
)
assert structural_source != original
assert "resolved_path = absreal(ap)" in structural_source
assert "shr_files" not in structural_source.split("def canonical")[1].split("def dcanonical")[0]
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core fix idea as the real _canonical_shr() (deny resolution outside
# the allow-listed shr_files subset when the node is a restricted share)
# but a materially different implementation: an early-return helper
# _shr_check() instead of the real patch's inline assert+if block, a
# different not-allowed sentinel (raises instead of returning "\\n\\n"),
# and no dependency on self.shr_src at all (compares directly against
# self.realpath) -- genuinely enforces the same restriction, different
# code shape/name from the real patched_source.py.
SAFE_BLOCK = '''    def _shr_check(self, ap: str) -> None:
        if not self.shr_files:
            return
        base = os.path.basename(ap)
        allowed_dir = absreal(self.realpath)
        if os.path.dirname(absreal(ap)) != allowed_dir or base not in self.shr_files:
            raise Pebkac(403, "file not in share")

    def canonical(self, rem: str, resolve: bool = True) -> str:
        """returns the canonical path (fully-resolved absolute fs path)"""
        ap = self.realpath
        if rem:
            ap += "/" + rem

        rap = absreal(ap)
        self._shr_check(rap)
        return rap if resolve else ap'''
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "_shr_check" in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Same visible shape (a method returning an absolute resolved path, same
# signature style) but this sibling is the read-only history/log path
# resolver -- it is used ONLY for copyparty's own internal history database
# location (self.histpath), which is never derived from user-supplied
# `rem` and never associated with a shr_files-restricted share node at
# all (history paths are server-side, not exposed through the share
# filesystem). No user-controlled path traversal is reachable through it,
# so the missing shr_files check is irrelevant here -- genuinely safe
# despite the structural resemblance to canonical().
BENIGN_SOURCE = '''import os


def absreal(path: str) -> str:
    return os.path.realpath(os.path.abspath(path))


class HistoryPathResolver:
    """Resolves the server-side history-database path for a volume.

    Unlike VFS.canonical(), this never takes attacker-influenced input --
    `histpath` is set once from server config at startup, never from a
    request path -- so there is no share-restriction to bypass here.
    """

    def __init__(self, histpath: str) -> None:
        self.histpath = histpath

    def canonical_history_path(self, resolve: bool = True) -> str:
        ap = self.histpath
        return absreal(ap) if resolve else ap
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "shr_files" not in BENIGN_SOURCE
assert "rem" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0043.")
