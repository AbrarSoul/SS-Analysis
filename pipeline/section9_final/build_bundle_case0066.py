"""
Section 9 ground-truth test bundle: CASE-0066
(NodeBB/NodeBB, CVE-2023-30591, CWE-241/CWE-754 improper handling of an
unexpected data type / improper exceptional-condition handling).

Core vulnerable mechanism: `onMessage()` receives `eventName` directly
from the socket.io payload -- fully attacker-controlled, so it can be any
JSON-serializable value, not just a string. When it isn't a string, the
code calls `String(eventName)` to build an error message. `String()`
invokes the value's OWN `toString()`/`Symbol.toStringTag` machinery if
`eventName` is an object -- a client can send an object whose `toString`
throws, blocks, or otherwise misbehaves, and that runs with the server's
own privileges during message handling. The fix replaces `String(eventName)`
with `typeof eventName`, which is a language-level operator that always
returns a small fixed string ("object", "number", "boolean", ...) and
NEVER invokes any method on the value itself -- the value's own
(potentially attacker-crafted) behavior can never run.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0066"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = '''	if (typeof eventName !== 'string') {
		const escapedName = validator.escape(String(eventName));
		return callback({ message: `[[error:invalid-event, ${escapedName}]]` });
	}'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename onMessage -> handleSocketMessage, eventName -> messageName
# throughout. Same exact String(eventName) call on an untrusted,
# potentially-object value.
renamed_source = original.replace("async function onMessage(socket, payload) {", "async function handleSocketMessage(socket, payload) {")
# onMessage is also referenced by name as a callback passed to als.run()
# elsewhere in this file (onConnection()) -- must be renamed there too,
# or that call site would reference an undefined function at runtime.
renamed_source = renamed_source.replace(
    "als.run({ uid: socket.uid }, onMessage, socket, payload);",
    "als.run({ uid: socket.uid }, handleSocketMessage, socket, payload);",
)
renamed_source = renamed_source.replace("const eventName = payload.data[0];", "const messageName = payload.data[0];")
renamed_source = renamed_source.replace(
    VULNERABLE_BLOCK,
    '''	if (typeof messageName !== 'string') {
		const escapedName = validator.escape(String(messageName));
		return callback({ message: `[[error:invalid-event, ${escapedName}]]` });
	}''',
)
renamed_source = renamed_source.replace("!eventName", "!messageName").replace("eventName.split", "messageName.split").replace(
    "String(eventName)", "String(messageName)"
).replace("${eventName}", "${messageName}").replace("push(eventName)", "push(messageName)").replace(
    "eventName.startsWith", "messageName.startsWith"
).replace("socket, eventName, params", "socket, messageName, params")
# Deliberately NOT touching the unrelated `eventName:` object-literal key
# in Sockets.warnDeprecated() elsewhere in this same file -- that's a
# different function's own property name, not a reference to this
# function's renamed local variable, and renaming it would just be noise.
assert "async function handleSocketMessage(socket, payload) {" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting.
# Same exact String(eventName) call, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''	const isStringEvent = typeof eventName === 'string';
	if (!isStringEvent) {
		const stringified = String(eventName);
		const escapedName = validator.escape(stringified);
		return callback({ message: `[[error:invalid-event, ${escapedName}]]` });
	}''',
)
assert structural_source != original
assert "const isStringEvent = typeof eventName === 'string';" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (never invoke the untrusted value's own
# toString()/valueOf() machinery) but a materially different technique:
# Object.prototype.toString.call(eventName) -- the GENERIC, non-
# overridable base Object stringifier (yields "[object Object]",
# "[object Array]", etc.) -- instead of the real patch's `typeof`
# operator. Still never runs the value's own overridden toString, but a
# different mechanism/output shape.
safe_block = '''	if (typeof eventName !== 'string') {
		const safeDescription = Object.prototype.toString.call(eventName);
		const escapedName = validator.escape(safeDescription);
		return callback({ message: `[[error:invalid-event, ${escapedName}]]` });
	}'''
safe_source = original.replace(VULNERABLE_BLOCK, safe_block)
assert safe_source != original
assert "Object.prototype.toString.call" in safe_source

# --- Verify this genuinely never invokes a malicious custom toString() ---
import subprocess

node_check = """
const validator = { escape: (s) => s };
let toStringWasCalled = false;
const malicious = {
  toString() { toStringWasCalled = true; throw new Error('pwned'); }
};
const eventName = malicious;
if (typeof eventName !== 'string') {
  const safeDescription = Object.prototype.toString.call(eventName);
  validator.escape(safeDescription);
}
if (toStringWasCalled) {
  console.error('FAIL: malicious toString() was invoked');
  process.exit(1);
}
console.log('OK: Object.prototype.toString.call never invoked the object\\'s own toString');
"""
proc = subprocess.run(["node", "-e", node_check], capture_output=True, text=True)
assert proc.returncode == 0, f"safe variant failed live verification: {proc.stdout} {proc.stderr}"

(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Same visible shape (call String(value) on a variable and use the
# result in a message) but the value here is always one of a small,
# fixed set of internal enum-like constants defined in this module --
# never anything read from an incoming socket payload -- so there is no
# way a client could ever supply an object with a malicious toString()
# that reaches this call, unlike onMessage()'s eventName.
BENIGN_SOURCE = '''const CONNECTION_STATE = Object.freeze({ CONNECTED: 1, DISCONNECTED: 0 });

function describeConnectionState(state) {
  // state is always CONNECTION_STATE.CONNECTED or .DISCONNECTED, both
  // fixed numeric constants defined above -- never a value taken from
  // an incoming socket message, so String() here can never invoke an
  // attacker-supplied toString().
  return `connection state: ${String(state)}`;
}

module.exports = { CONNECTION_STATE, describeConnectionState };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "payload" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0066.")
