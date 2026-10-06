"""
Section 9 ground-truth test bundle: CASE-0255
(patriksimek/vm2, lib/setup-sandbox.js Error.prepareStackTrace setter /
newWrapped, CVE-2023-29017, CWE-913 improperly controlled modification of a
dynamically-determined object attribute; sandbox escape).

Core vulnerable mechanism: when code running inside the sandbox sets
`Error.prepareStackTrace = fn`, vm2 installs `newWrapped` as the REAL
(host-realm) `Error.prepareStackTrace`, so it runs whenever the host's own code
reads `.stack` on an Error. `newWrapped(error, sst)` receives `sst`, the
call-site array, exactly as V8 built it in the caller's realm -- which, for an
error thrown by host code, is a HOST-REALM array, not the sandbox's own copy.
The vulnerable code writes into it directly: `sst[i] = new CallSite(cs)`. Sandboxed
code therefore gets to run arbitrary property assignments on an array object that
lives in the host realm, which is the primitive the public exploit chain uses to
reach the host's `Function` constructor and break out. The upstream fix calls
`ensureThis(sst)` (vm2's bridge function, which returns a sandbox-side proxy/copy
whenever the value did not already belong to the sandbox realm) and mutates in
place ONLY when `sst === sandboxSst`, i.e. only when the array already belonged to
the sandbox; for any array that needed bridging it builds a brand-new array and
never touches the original.

Sibling sites: `newWrapped` is the only place in the file that receives and writes
into a call-site array from `Error.prepareStackTrace`.

Verification: the `newWrapped` closure (verbatim from `const newWrapped = (error, sst)
=> {` to its closing `};`) is extracted from each full file and instantiated with a
harness-supplied `ensureThis` that mimics vm2's real bridge contract: identity for an
array already tagged as "from the sandbox realm", a brand-new array (mapped
1:1, entries copied) for one that is not. Two calls are made: a "local" sst (already
sandbox-realm) and a "foreign" sst (needs bridging, standing in for a host-realm
array). The test checks whether the ORIGINAL foreign array object was written into.

Every variant is the FULL real file (byte-identical to vm2 3.9.14 for the
vulnerable form and 3.9.15 for the patched form). The setter itself has no name (it
implements the `Error.prepareStackTrace` accessor via `Reflect.defineProperty`), so
nothing outside `newWrapped`'s own body is renamed; the renamed variant renames
`newWrapped`'s locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0255"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

NW = "\t\t\tconst newWrapped = (error, sst) => {\n\t\t\t\tif (localArrayIsArray(sst)) {\n\t\t\t\t\tfor (let i=0; i < sst.length; i++) {\n\t\t\t\t\t\tconst cs = sst[i];\n\t\t\t\t\t\tif (typeof cs === 'object' && localReflectGetPrototypeOf(cs) === OriginalCallSite.prototype) {\n\t\t\t\t\t\t\tsst[i] = new CallSite(cs);\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t\treturn value(error, sst);\n\t\t\t};\n"
assert original.count(NW) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, NW, "\t\t\tconst newWrapped = (thrownError, callSites) => {\n\t\t\t\tif (localArrayIsArray(callSites)) {\n\t\t\t\t\tfor (let idx=0; idx < callSites.length; idx++) {\n\t\t\t\t\t\tconst entry = callSites[idx];\n\t\t\t\t\t\tif (typeof entry === 'object' && localReflectGetPrototypeOf(entry) === OriginalCallSite.prototype) {\n\t\t\t\t\t\t\tcallSites[idx] = new CallSite(entry);\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t\treturn value(thrownError, callSites);\n\t\t\t};\n")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, NW, "\t\t\tconst newWrapped = (error, sst) => {\n\t\t\t\trewrapCallSites(sst);\n\t\t\t\treturn value(error, sst);\n\t\t\t};\n")
v2 = swap(v2, "\t\t\tconst newWrapped = (error, sst) => {\n\t\t\t\trewrapCallSites(sst);\n\t\t\t\treturn value(error, sst);\n\t\t\t};\n",
          "\t\t\tfunction rewrapCallSites(sst) {\n\t\t\t\tif (localArrayIsArray(sst)) {\n\t\t\t\t\tfor (let i=0; i < sst.length; i++) {\n\t\t\t\t\t\tconst cs = sst[i];\n\t\t\t\t\t\tif (typeof cs === 'object' && localReflectGetPrototypeOf(cs) === OriginalCallSite.prototype) {\n\t\t\t\t\t\t\tsst[i] = new CallSite(cs);\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t\tconst newWrapped = (error, sst) => {\n\t\t\t\trewrapCallSites(sst);\n\t\t\t\treturn value(error, sst);\n\t\t\t};\n")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same idea as upstream (never write into an array that needed bridging) expressed
# with an explicit ownership flag from ensureThis's return value instead of `===`.
v3 = swap(original, NW, "\t\t\tconst newWrapped = (error, sst) => {\n\t\t\t\tif (localArrayIsArray(sst)) {\n\t\t\t\t\tconst bridged = ensureThis(sst);\n\t\t\t\t\tconst ownedBySandbox = bridged === sst;\n\t\t\t\t\tconst source = ownedBySandbox ? sst : bridged;\n\t\t\t\t\tconst rewrapped = [];\n\t\t\t\t\tfor (let i=0; i < source.length; i++) {\n\t\t\t\t\t\tconst cs = source[i];\n\t\t\t\t\t\tconst wrappedCs = (typeof cs === 'object' && localReflectGetPrototypeOf(cs) === OriginalCallSite.prototype) ? new CallSite(cs) : cs;\n\t\t\t\t\t\tif (ownedBySandbox) {\n\t\t\t\t\t\t\tsst[i] = wrappedCs;\n\t\t\t\t\t\t} else {\n\t\t\t\t\t\t\tlocalReflectDefineProperty(rewrapped, i, {\n\t\t\t\t\t\t\t\t__proto__: null,\n\t\t\t\t\t\t\t\tvalue: wrappedCs,\n\t\t\t\t\t\t\t\tenumerable: true,\n\t\t\t\t\t\t\t\tconfigurable: true,\n\t\t\t\t\t\t\t\twritable: true\n\t\t\t\t\t\t\t});\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t\tsst = ownedBySandbox ? sst : rewrapped;\n\t\t\t\t} else {\n\t\t\t\t\tsst = ensureThis(sst);\n\t\t\t\t}\n\t\t\t\treturn value(error, sst);\n\t\t\t};\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: rewrap entries of a list, but always
// into a freshly allocated array, so the caller's original array (whichever realm
// it came from) is never written into.
function rewrapAll(list, wrap) {
	const out = [];
	for (let i = 0; i < list.length; i++) {
		out[i] = wrap(list[i]);
	}
	return out;
}

module.exports = { rewrapAll };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
