"""
Section 9 ground-truth test bundle: CASE-0055
(Josh-XT/AGiXT, CVE-2026-39981, CWE-22 path traversal).

Core vulnerable mechanism: `safe_join()` builds a path via
`os.path.normpath(os.path.join(WORKING_DIRECTORY, *paths.split("/")))`.
`normpath()` only collapses redundant separators and resolves `.`/`..`
segments SYNTACTICALLY -- it does not clip a result that ends up outside
the base directory, and it never resolves symlinks. A caller-supplied
path containing enough `../` segments (e.g. `"../../etc/passwd"`) still
normalizes to a path outside `WORKING_DIRECTORY`, which the function then
happily creates directories for and returns -- classic path traversal.
The fix additionally resolves both the base and the candidate path with
`os.path.realpath()` (also collapsing symlinks) and explicitly verifies
the result is still inside the working directory before using it.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0055"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    def safe_join(self, paths) -> str:
        """
        Safely join paths together

        Args:
        paths (str): The paths to join

        Returns:
        str: The joined path
        """
        if "/path/to/" in paths:
            paths = paths.replace("/path/to/", "")
        new_path = os.path.normpath(
            os.path.join(self.WORKING_DIRECTORY, *paths.split("/"))
        )
        path_dir = os.path.dirname(new_path)
        os.makedirs(path_dir, exist_ok=True)
        return new_path'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename safe_join -> resolve_workspace_path, new_path -> target_path,
# path_dir -> target_dir. Same exact unchecked normpath-only join.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def resolve_workspace_path(self, paths) -> str:
        """
        Safely join paths together

        Args:
        paths (str): The paths to join

        Returns:
        str: The joined path
        """
        if "/path/to/" in paths:
            paths = paths.replace("/path/to/", "")
        target_path = os.path.normpath(
            os.path.join(self.WORKING_DIRECTORY, *paths.split("/"))
        )
        target_dir = os.path.dirname(target_path)
        os.makedirs(target_dir, exist_ok=True)
        return target_path''',
)
assert "def resolve_workspace_path(self, paths) -> str:" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting.
# Same exact unchecked traversal, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def safe_join(self, paths) -> str:
        """
        Safely join paths together

        Args:
        paths (str): The paths to join

        Returns:
        str: The joined path
        """
        contains_placeholder = "/path/to/" in paths
        cleaned_paths = paths.replace("/path/to/", "") if contains_placeholder else paths
        joined = os.path.join(self.WORKING_DIRECTORY, *cleaned_paths.split("/"))
        new_path = os.path.normpath(joined)
        path_dir = os.path.dirname(new_path)
        os.makedirs(path_dir, exist_ok=True)
        return new_path''',
)
assert structural_source != original
assert "contains_placeholder = \"/path/to/\" in paths" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (verify the resolved path stays within the
# working directory) but a materially different technique: uses
# os.path.commonpath() to check containment instead of the real patch's
# realpath()+startswith(base + os.sep) string check -- genuinely rejects
# any path that escapes WORKING_DIRECTORY, different implementation shape.
SAFE_SOURCE = '''import os


class SafePathJoiner:
    def __init__(self, working_directory: str):
        self.WORKING_DIRECTORY = working_directory

    def safe_join(self, paths) -> str:
        if "/path/to/" in paths:
            paths = paths.replace("/path/to/", "")
        base = os.path.realpath(self.WORKING_DIRECTORY)
        candidate = os.path.realpath(
            os.path.normpath(os.path.join(self.WORKING_DIRECTORY, *paths.split("/")))
        )
        try:
            common = os.path.commonpath([base, candidate])
        except ValueError:
            common = None
        if common != base:
            raise PermissionError("Path traversal detected: refusing to access path outside workspace")
        path_dir = os.path.dirname(candidate)
        os.makedirs(path_dir, exist_ok=True)
        return candidate
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "os.path.commonpath" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (join a caller-supplied path fragment onto a base
# directory and normalize it) but this sibling operates on a FIXED,
# hard-coded set of report filenames chosen from an enum, never on an
# arbitrary caller-supplied path string -- there is no `../`-bearing
# input this could ever receive, unlike safe_join()'s free-form `paths`
# argument taken straight from agent/tool input.
BENIGN_SOURCE = '''import os
from enum import Enum


class ReportKind(Enum):
    SUMMARY = "summary.txt"
    METRICS = "metrics.json"


class ReportPathResolver:
    def __init__(self, working_directory: str):
        self.WORKING_DIRECTORY = working_directory

    def report_path(self, kind: ReportKind) -> str:
        # kind is always one of the fixed ReportKind members -- never a
        # caller-supplied string -- so there is no path fragment here an
        # attacker could ever influence, let alone fill with "../".
        return os.path.normpath(os.path.join(self.WORKING_DIRECTORY, kind.value))
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "paths.split" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0055.")
