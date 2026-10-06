"""
Section 9 ground-truth test bundle: CASE-0091
(airlinklabs/daemon, CVE-2025-57802, CWE-61 symlink following).

Core vulnerable mechanism: `sanitizePath()` only checks, textually, that
`path.join(base, relativePath)` still starts with `base`. It never looks at
the file system, so a symbolic link INSIDE the base directory that points
outside it (e.g. volumes/1/link -> /etc) passes the check, and the
upload / create-empty-file / append-file handlers then read or write
through the link, escaping the volume. The upstream fix switches to
path.resolve, makes the function async and rejects symlinks with
fs.lstat().

Every variant is the FULL real file with sanitizePath replaced (the
renamed variant also renames its three call sites).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0091"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.ts").read_text().splitlines()) + "\n"

BLOCK = '''const sanitizePath = (base: string, relativePath: string): string => {
    const fullPath = path.join(base, relativePath);
    if (!fullPath.startsWith(base)) {
        throw new Error('Invalid path: Directory traversal is not allowed.');
    }
    return fullPath;
};
'''
assert original.count(BLOCK) == 1
assert original.count("sanitizePath(") == 3  # the 3 call sites (declaration is an arrow const)


def build(new_block, text=None):
    return (text or original).replace(BLOCK, new_block)


# --- Variant 1: renamed vulnerable variant ---
renamed = build('''const resolveWithinRoot = (root: string, userPath: string): string => {
    const joined = path.join(root, userPath);
    if (!joined.startsWith(root)) {
        throw new Error('Invalid path: Directory traversal is not allowed.');
    }
    return joined;
};
''')
renamed = re.sub(r"\bsanitizePath\(", "resolveWithinRoot(", renamed)
assert "sanitizePath" not in renamed and renamed.count("resolveWithinRoot(") == 3
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.ts").write_text(build('''const sanitizePath = (base: string, relativePath: string): string => {
    const fullPath = path.join(base, relativePath);
    const isInsideBase = fullPath.startsWith(base);
    if (isInsideBase === false) {
        throw new Error('Invalid path: Directory traversal is not allowed.');
    }
    return fullPath;
};
'''))

# --- Variant 3: transformed safe variant ---
# Stays synchronous (call sites unchanged): resolves symlinks of the deepest
# EXISTING ancestor with realpathSync and checks containment against the
# real base with path.relative, instead of upstream's async lstat check on
# the final component only.
SAFE = '''const sanitizePath = (base: string, relativePath: string): string => {
    const fullPath = path.resolve(base, relativePath);
    const lexical = path.relative(base, fullPath);
    if (lexical.startsWith('..') || path.isAbsolute(lexical)) {
        throw new Error('Invalid path: Directory traversal is not allowed.');
    }
    // Resolve symlinks of the deepest ancestor that already exists (the target
    // itself may not exist yet, e.g. when creating a new file).
    let probe = fullPath;
    while (probe !== base && !existsSync(probe)) {
        probe = path.dirname(probe);
    }
    const realProbe = realpathSync(probe);
    const realBase = existsSync(base) ? realpathSync(base) : base;
    const resolved = path.relative(realBase, realProbe);
    if (resolved.startsWith('..') || path.isAbsolute(resolved)) {
        throw new Error('Invalid path: Symlinks leaving the base directory are not allowed.');
    }
    return fullPath;
};
'''
safe = build(SAFE).replace("import fs from 'fs/promises';\n", "import fs from 'fs/promises';\nimport { existsSync, realpathSync } from 'fs';\n", 1)
assert "import { existsSync, realpathSync } from 'fs';" in safe
(CASE_DIR / "variant_safe_01.ts").write_text(safe)

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.ts").write_text('''import path from 'path';

const ASSET_FILES: Record<string, string> = {
    logo: 'img/logo.png',
    favicon: 'img/favicon.ico',
};

/**
 * Same path.join(base, x) + startsWith(base) shape, but the relative part
 * comes only from a fixed table of developer-written constants keyed by a
 * whitelisted name; no request-supplied path (and no user-writable
 * directory that could contain a symlink) is ever involved.
 */
export const resolveBundledAsset = (base: string, name: string): string => {
    const relative = ASSET_FILES[name];
    if (relative === undefined) {
        throw new Error('Unknown asset');
    }
    const fullPath = path.join(base, relative);
    if (!fullPath.startsWith(base)) {
        throw new Error('Invalid path');
    }
    return fullPath;
};
''')
print("Wrote 4 new samples for CASE-0091.")
