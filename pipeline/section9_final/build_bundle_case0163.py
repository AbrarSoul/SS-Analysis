"""
Section 9 ground-truth test bundle: CASE-0163
(feross/git-pull-or-clone, index.js gitPullOrClone, CVE-2022-24437,
CWE-88 argument injection).

Core vulnerable mechanism: `gitClone` runs
`git clone <flag> <url> <outPath>` with `url` (and `outPath`) as ordinary
argv entries. A `url` that begins with `-`, such as
`--upload-pack=touch /tmp/pwned`, is parsed by git as an OPTION, and
`--upload-pack` makes git run the given command. The upstream fix inserts the
`--` end-of-options marker before the two positional arguments.

Measured with the real git: `git clone --single-branch "--upload-pack=touch
X" src.git` runs the command (the file is created), whereas
`git clone --single-branch -- "--upload-pack=touch X" src.git` treats it as a
repository name and runs nothing. The library only takes the clone path when
`outPath` is not readable and writable (`fs.access`), so the tests record the
argv that reaches git through a fake `git` on PATH, and also run the real git
against an existing read-only repository as `outPath` (which sends the call
down the clone path).

Sibling sites: `gitPull` passes no user-controlled positional argument (the
`url` there is only used in an error message and `outPath` is a `cwd`).

Every variant is the FULL real file. gitPullOrClone is the module export, so
the renamed variant keeps that name and renames the inner functions,
parameters and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0163"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

ARGS = "    const args = ['clone', flag, url, outPath]\n"
assert original.count(ARGS) == 1
s = original.index("function gitPullOrClone (url, outPath, opts, cb) {\n")
e = original.index("\nfunction spawn (", s)
CORE = original[s:e]


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        parts = re.split(r"""('(?:[^'\\]|\\.)*')""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


pairs = (("url", "repoUrl"), ("outPath", "destDir"), ("opts", "options"), ("cb", "done"), ("depth", "cloneDepth"),
         ("flag", "depthFlag"), ("args", "gitArgs"), ("err", "error"), ("gitClone", "cloneRepo"), ("gitPull", "pullRepo"))
core = rename(CORE, pairs)
# gitPullOrClone itself stays: it is the export
core = core.replace("function pullRepoOrClone", "function gitPullOrClone")
v1 = original[:s] + core + original[e:]
v1 = v1.replace("function spawn (command, args, opts, cb) {", "function spawn (command, args, opts, cb) {")
assert "function gitPullOrClone (repoUrl, destDir, options, done) {" in v1
assert "const gitArgs = ['clone', depthFlag, repoUrl, destDir]" in v1 and "cloneRepo()" in v1 and "pullRepo()" in v1
assert "if (error) error.message += ' (git clone) (' + repoUrl + ')'" in v1
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, ARGS, "    const args = cloneArgs(flag, url, outPath)\n")
v2 = swap(v2, "function spawn (command, args, opts, cb) {", '''function cloneArgs (flag, url, outPath) {
  return ['clone', flag].concat([url, outPath])
}

function spawn (command, args, opts, cb) {''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Refuse any url or outPath that starts with '-' (it would be parsed as an
# option) before spawning; upstream inserts the `--` end-of-options marker.
v3 = swap(original, ARGS, '''    if (url.startsWith('-') || outPath.startsWith('-')) {
      return cb(new Error('Invalid url or path: must not start with "-"'))
    }
    const args = ['clone', flag, url, outPath]
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''const crossSpawn = require('cross-spawn')

/**
 * Same crossSpawn('git', args, ...) call as the clone helper, but every
 * argument is a developer-written constant and the repository is chosen only
 * through `cwd`, so no caller-supplied string can be parsed as a git option.
 */
function recentCommits (repoDir, cb) {
  const child = crossSpawn('git', ['log', '--oneline', '-n', '5'], { cwd: repoDir, stdio: 'ignore' })
  child.on('error', cb)
  child.on('close', function (code) {
    cb(code === 0 ? null : new Error('Non-zero exit code: ' + code))
  })
}

module.exports = recentCommits
'''
assert "developer-written constant" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0163.")
