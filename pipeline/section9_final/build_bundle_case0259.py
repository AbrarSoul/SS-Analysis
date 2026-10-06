"""
Section 9 ground-truth test bundle: CASE-0259
(pkrumins/node-tree-kill, index.js module.exports, CVE-2019-15598,
CWE-78 OS command injection).

Core vulnerable mechanism: on Windows, the exported function kills a process
tree with `exec('taskkill /pid ' + pid + ' /T /F', callback)`. `exec` runs its
argument through a shell, and `pid` is concatenated into the command string with
no validation, so a caller (or any code path that forwards an
externally-influenced value as `pid`, e.g. a request parameter used to identify
a job/process) can pass a string such as `"1 & calc.exe"` or
`"1; rm -rf /tmp/x"` and have the extra command run by the shell alongside
(or instead of) the intended `taskkill`. `darwin`/`linux` build the process
tree with `spawn(cmd, [args])`, which does not go through a shell, so they are
not affected. The upstream fix adds `if (typeof pid !== "number") { throw new
Error("pid must be a number"); }` at the very top, before the platform switch,
so a string `pid` never reaches `exec`.

Sibling sites: `exec` with string concatenation is the only shell-interpreted
call in the file (the `darwin`/`linux`/`buildProcessTree` paths use
`spawn(cmd, [args])`, an argv array, which is not shell-parsed regardless of
`pid`'s type).

Verification: each full file is loaded as a real Node module with
`process.platform` forced to `'win32'` (`Object.defineProperty`) and
`child_process.exec` replaced by a recorder (no shell command is actually run);
the exported function is called with a `pid` string that carries a shell
metacharacter payload, and the recorded command string is inspected for the
injected fragment. A normal numeric `pid` is used as a control.

Every variant is the FULL real file. `module.exports` is the package's only
export (required by callers as `require('tree-kill')`), so its call signature is
kept; the renamed variant renames its locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0259"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


HEAD = """module.exports = function (pid, signal, callback) {
    var tree = {};
    var pidsToProcess = {};
    tree[pid] = [];
    pidsToProcess[pid] = 1;
"""
assert original.count(HEAD) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, HEAD, """module.exports = function (targetPid, sig, done) {
    var tree = {};
    var pidsToProcess = {};
    tree[targetPid] = [];
    pidsToProcess[targetPid] = 1;
""")
v1 = swap(v1, """    if (typeof signal === 'function' && callback === undefined) {
      callback = signal;
      signal = undefined;
    }

    switch (process.platform) {
    case 'win32':
        exec('taskkill /pid ' + pid + ' /T /F', callback);
        break;
    case 'darwin':
        buildProcessTree(pid, tree, pidsToProcess, function (parentPid) {
          return spawn('pgrep', ['-P', parentPid]);
        }, function () {
            killAll(tree, signal, callback);
        });
        break;""", """    if (typeof sig === 'function' && done === undefined) {
      done = sig;
      sig = undefined;
    }

    switch (process.platform) {
    case 'win32':
        exec('taskkill /pid ' + targetPid + ' /T /F', done);
        break;
    case 'darwin':
        buildProcessTree(targetPid, tree, pidsToProcess, function (parentPid) {
          return spawn('pgrep', ['-P', parentPid]);
        }, function () {
            killAll(tree, sig, done);
        });
        break;""")
v1 = swap(v1, """    default: // Linux
        buildProcessTree(pid, tree, pidsToProcess, function (parentPid) {
          return spawn('ps', ['-o', 'pid', '--no-headers', '--ppid', parentPid]);
        }, function () {
            killAll(tree, signal, callback);
        });
        break;
    }
};""", """    default: // Linux
        buildProcessTree(targetPid, tree, pidsToProcess, function (parentPid) {
          return spawn('ps', ['-o', 'pid', '--no-headers', '--ppid', parentPid]);
        }, function () {
            killAll(tree, sig, done);
        });
        break;
    }
};""")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, "    case 'win32':\n        exec('taskkill /pid ' + pid + ' /T /F', callback);\n        break;\n",
          "    case 'win32':\n        killWindowsTree(pid, callback);\n        break;\n")
v2 = swap(v2, "function killAll (tree, signal, callback) {", """function killWindowsTree(pid, callback) {
    exec('taskkill /pid ' + pid + ' /T /F', callback);
}

function killAll (tree, signal, callback) {""")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "    case 'win32':\n        exec('taskkill /pid ' + pid + ' /T /F', callback);\n        break;\n",
          "    case 'win32':\n        if (!Number.isInteger(pid)) {\n            var err = new Error('pid must be an integer, got: ' + JSON.stringify(pid));\n            if (callback) return callback(err);\n            throw err;\n        }\n        exec('taskkill /pid ' + pid + ' /T /F', callback);\n        break;\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: build a shell command from a value,
// but the value is an internal, fixed job-type enum, never data an external
// caller supplies.
var exec = require('child_process').exec;

var JOB_COMMANDS = { backup: 'run-backup.sh', cleanup: 'run-cleanup.sh' };

module.exports = function runJob(jobType, callback) {
    var script = JOB_COMMANDS[jobType];
    if (!script) return callback(new Error('unknown job type'));
    exec('./scripts/' + script, callback);
};
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
