"""
Section 9 ground-truth test bundle: CASE-0060
(Mintplex-Labs/anything-llm, CVE-2026-45403, CWE-59 improper link
resolution before file access).

Core vulnerable mechanism: `copyRecursive()` uses `fs.stat(source)`, which
transparently FOLLOWS symbolic links -- if an AI agent's filesystem plugin
is pointed at a path that is (or contains) a symlink, the copy silently
follows it and reads/copies whatever the symlink actually points to,
potentially outside the intended sandboxed directory. The fix switches to
`fs.lstat()` (which reports on the link itself, not its target) and
explicitly rejects any symlink with a thrown error rather than following
it.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0060"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = '''async function copyRecursive(source, destination) {
  const stats = await fs.stat(source);

  if (stats.isDirectory()) {
    await fs.mkdir(destination, { recursive: true });
    const entries = await fs.readdir(source);
    for (const entry of entries) {
      await copyRecursive(
        path.join(source, entry),
        path.join(destination, entry)
      );
    }
  } else {
    await fs.copyFile(source, destination);
  }
}'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename copyRecursive -> recursiveCopy, stats -> fileStats. Same exact
# symlink-following fs.stat() call.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''async function recursiveCopy(source, destination) {
  const fileStats = await fs.stat(source);

  if (fileStats.isDirectory()) {
    await fs.mkdir(destination, { recursive: true });
    const entries = await fs.readdir(source);
    for (const entry of entries) {
      await recursiveCopy(
        path.join(source, entry),
        path.join(destination, entry)
      );
    }
  } else {
    await fs.copyFile(source, destination);
  }
}''',
)
assert "async function recursiveCopy(source, destination) {" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting.
# Same exact symlink-following stat call, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''async function copyRecursive(source, destination) {
  const stats = await fs.stat(source);
  const isDir = stats.isDirectory();

  if (!isDir) {
    await fs.copyFile(source, destination);
    return;
  }

  await fs.mkdir(destination, { recursive: true });
  const entries = await fs.readdir(source);
  for (const entry of entries) {
    await copyRecursive(
      path.join(source, entry),
      path.join(destination, entry)
    );
  }
}''',
)
assert structural_source != original
assert "const isDir = stats.isDirectory();" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (never follow a symlink during the copy) but
# a materially different technique: an ALLOWLIST check (only proceed if
# the entry is a regular file OR directory) rather than the real patch's
# explicit isSymbolicLink() denylist check -- genuinely rejects symlinks
# (and any other non-regular entry, e.g. sockets/FIFOs/device files too),
# different implementation shape.
SAFE_SOURCE = '''const fs = require("fs/promises");
const path = require("path");

async function copyRecursive(source, destination) {
  const lstat = await fs.lstat(source);

  if (lstat.isDirectory()) {
    await fs.mkdir(destination, { recursive: true });
    const entries = await fs.readdir(source);
    for (const entry of entries) {
      await copyRecursive(
        path.join(source, entry),
        path.join(destination, entry)
      );
    }
    return;
  }

  if (!lstat.isFile()) {
    throw new Error(
      `Refusing to copy non-regular entry (symlink, socket, or device): ${source}`
    );
  }

  await fs.copyFile(source, destination);
}

module.exports = { copyRecursive };
'''
(CASE_DIR / "variant_safe_01.js").write_text(SAFE_SOURCE)
assert "lstat" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (a recursive copy walking directories via fs.stat())
# but this sibling only ever copies from a source directory it JUST
# created itself moments earlier via fs.mkdtemp() -- never a path an
# agent/tool or user supplied -- so there is no way a symlink planted by
# an attacker could ever be the copy source, unlike copyRecursive()'s
# externally-supplied `source` argument.
BENIGN_SOURCE = '''const fs = require("fs/promises");
const os = require("os");
const path = require("path");

async function snapshotOwnScratchDir() {
  // sourceDir is always a directory THIS function just created via
  // mkdtemp() a moment earlier -- never derived from any external input,
  // so it can never contain an attacker-planted symlink.
  const sourceDir = await fs.mkdtemp(path.join(os.tmpdir(), "scratch-"));
  await fs.writeFile(path.join(sourceDir, "marker.txt"), "ok");

  const destination = path.join(os.tmpdir(), "scratch-snapshot");
  const stats = await fs.stat(sourceDir);
  if (stats.isDirectory()) {
    await fs.mkdir(destination, { recursive: true });
    const entries = await fs.readdir(sourceDir);
    for (const entry of entries) {
      await fs.copyFile(
        path.join(sourceDir, entry),
        path.join(destination, entry)
      );
    }
  }
  return destination;
}

module.exports = { snapshotOwnScratchDir };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "copyRecursive(source" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0060.")
