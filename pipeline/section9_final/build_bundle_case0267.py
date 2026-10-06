"""
Section 9 ground-truth test bundle: CASE-0267
(psf/requests, src/requests/utils.py extract_zipped_paths, CVE-2026-25645,
CWE-377 insecure temporary file).

Core vulnerable mechanism: `extract_zipped_paths` is used to resolve a path
that points to a member INSIDE a zip archive (e.g. a CA bundle path
configured via `REQUESTS_CA_BUNDLE` that lives inside a zipped Python
package) by extracting that member to disk and returning the extracted
file's path. It extracts to a PREDICTABLE, shared location --
`os.path.join(tempfile.gettempdir(), member.split("/")[-1])`, i.e. the
member's bare filename directly under the system temp directory, the same
location every invocation (by any user, on a multi-user system where `/tmp`
is typically world-writable) will compute. Worse, it only writes there `if
not os.path.exists(extracted_path)` -- if a file ALREADY sits at that
guessable path, the function trusts it unconditionally and returns its path
without ever comparing its contents to the real zip member. An attacker
who can write to the shared temp directory (any local user, or anything
that can drop a file there first) can therefore pre-plant a file at the
predictable path before the victim's process runs; when the victim later
calls `extract_zipped_paths` for that same member name, they silently
receive the ATTACKER'S file instead of the real one -- e.g. a forged CA
certificate bundle used to make `requests` trust an attacker-controlled
root of trust for all HTTPS verification. The upstream fix replaces the
predictable-path-plus-existence-check with `tempfile.mkstemp(suffix=...)`,
which atomically creates a brand-new, uniquely-named, exclusively-owned
temp file (no predictable name to plant a file at, and no existence check
to fool) and always writes the real member's bytes into it.

Sibling sites: `atomic_open` (used by the OLD code path this fix removes)
already used `tempfile.mkstemp` correctly for the WRITE itself; the actual
defect was never in how bytes reached disk, only in the predictable
destination path and the trust-if-it-exists check gating whether to write
at all. There is one call site to fix.

Verification: each full file's `extract_zipped_paths` runs as real,
unmodified code -- the source file is copied over
`site-packages/requests/utils.py` inside a real virtualenv with `requests`
(and therefore `urllib3`) pip-installed, so every relative import (`from .
import certs`, `from ._internal_utils import ...`) resolves exactly as it
does in the shipped library, and the function is exercised through
`requests.utils.extract_zipped_paths` with a REAL zip file on a real
filesystem. A member named `payload-marker-xyz.txt` containing
`GOOD-CONTENT-FROM-ZIP` is zipped up; BEFORE calling the function, a file
is pre-planted at the predictable path
(`tempfile.gettempdir()/payload-marker-xyz.txt`) containing
`EVIL-PREPLANTED-CONTENT`, simulating an attacker who got there first. The
function is then called with a path pointing at that member inside the
real zip, and the CONTENT of the path it returns is inspected.

Every variant is the FULL real file. `extract_zipped_paths` is imported and
called by name elsewhere in `requests` (to resolve `REQUESTS_CA_BUNDLE`/
`CURL_CA_BUNDLE` when they point inside a zipped package), so its name and
single-argument signature are kept; the renamed variant renames its own
locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0267"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


CORE = """    # we have a valid zip archive and a valid member of that archive
    tmp = tempfile.gettempdir()
    extracted_path = os.path.join(tmp, member.split("/")[-1])
    if not os.path.exists(extracted_path):
        # use read + write to avoid the creating nested folders, we only want the file, avoids mkdir racing condition
        with atomic_open(extracted_path) as file_handler:
            file_handler.write(zip_file.read(member))
    return extracted_path"""
assert original.count(CORE) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, CORE, """    # we have a valid zip archive and a valid member of that archive
    tmp_dir = tempfile.gettempdir()
    dest_path = os.path.join(tmp_dir, member.split("/")[-1])
    if not os.path.exists(dest_path):
        # use read + write to avoid the creating nested folders, we only want the file, avoids mkdir racing condition
        with atomic_open(dest_path) as fh:
            fh.write(zip_file.read(member))
    return dest_path""")
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CORE, """    # we have a valid zip archive and a valid member of that archive
    extracted_path = _predictable_extracted_path(member)
    if not os.path.exists(extracted_path):
        # use read + write to avoid the creating nested folders, we only want the file, avoids mkdir racing condition
        with atomic_open(extracted_path) as file_handler:
            file_handler.write(zip_file.read(member))
    return extracted_path""")
v2 = swap(v2, "def extract_zipped_paths(path):", """def _predictable_extracted_path(member):
    tmp = tempfile.gettempdir()
    return os.path.join(tmp, member.split("/")[-1])


def extract_zipped_paths(path):""")
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (a fresh, uniquely-named temp file every
# call, never a predictable shared path) but built with
# tempfile.NamedTemporaryFile(delete=False) and an explicit .write(), in
# place of upstream's tempfile.mkstemp() + os.write()/os.close() pair.
v3 = swap(original, CORE, """    # we have a valid zip archive and a valid member of that archive
    suffix = os.path.splitext(member.split("/")[-1])[-1]
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as file_handler:
        file_handler.write(zip_file.read(member))
        extracted_path = file_handler.name

    return extracted_path""")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""
Standalone example of the same shape: cache a computed, expensive-to-derive
display label under a name built from its input, so repeat calls skip the
computation -- but the cache is process-local (an in-memory dict, never a
shared filesystem location another user could pre-populate), so an
existing entry being trusted is the intended behavior, not a security gap.
"""

_label_cache = {}


def cached_display_label(key, compute_fn):
    if key not in _label_cache:
        _label_cache[key] = compute_fn(key)
    return _label_cache[key]
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
