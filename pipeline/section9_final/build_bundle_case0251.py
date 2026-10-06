"""
Section 9 ground-truth test bundle: CASE-0251
(openstack/storlets, storlets/gateway/gateways/docker/gateway.py
StorletGatewayDocker.bring_from_cache, CVE-2024-28717, CWE-400 as labelled;
the mechanism is permissive modes on cached executable code).

Core vulnerable mechanism: the gateway keeps downloaded storlets (executable
jars run as root inside the Docker container) and their dependencies in a host
cache and copies them into the container's storlet directory. It creates those
directories with `os.makedirs(cache_dir, 0o755)` and
`os.makedirs(docker_storlet_path, 0o755)`, writes each file with
`open(path, 'wb')` (mode `0o666 & ~umask`, so `0o644` normally), and then applies the
permission bits carried in the object's metadata only to DEPENDENCIES
(`if not is_storlet: os.chmod(path, int(perm, 8))`). Storlet files are never
chmod'ed, and a dependency whose metadata says `0777` becomes world-writable.
Other local users can read every cached storlet and, for a group/world-writable
dependency or a `0o755` directory that they can write to through a permissive
ancestor, replace code that the gateway later copies into the container. The upstream
fix creates both directories `0o700`, chmods every cached file BEFORE the data is
written, and masks the metadata permissions with `& 0o700` (default `0o600`).

Measured caveat, kept in the manifest notes: `os.makedirs(path, 0o700)` still goes
through the process umask and only applies the mode to the leaf directory
(intermediate directories get the default), and the fixed code still creates the file
with the umask mode for an instant before `os.chmod`. The safe variant creates the file
with `os.open(..., mode)` so it never exists with wider permissions, and treats an
unparsable permission string as `0o600`.

Sibling sites: the two `os.makedirs(..., 0o755)` calls, the storlet-only skip of the
chmod and the post-write chmod are all changed by the upstream patch; the safe variant
fixes all of them. `shutil.copy2` into the container directory copies the cache file's
mode, so it inherits the fix.

Verification: `bring_from_cache` is extracted verbatim from each full file into a
class with stand-in `paths`/`sreq` objects, run against the REAL filesystem with umask
`0o022` for a storlet (metadata perm `0755`) and a dependency (metadata perm `0777`);
`open` is wrapped to read the file's real mode at each write and the resulting directory
and file modes are read back.

Every variant is the FULL real file. `bring_from_cache` is called by name from
`update_docker_container_from_cache`, so its name and signature are kept; the renamed
variant renames locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0251"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


MK1 = "            os.makedirs(cache_dir, 0o755)\n" if False else "        if not os.path.exists(cache_dir):\n            os.makedirs(cache_dir, 0o755)\n"
WRITE = '''            # bring the object from storge
            data_iter, perm = get_func(obj_name)

            # TODO(takashi): Do not directly write to target path
            with open(cache_target_path, 'wb') as fn:
                for data in data_iter:
                    fn.write(data)

            if not is_storlet:
                if not perm:
                    perm = '0600'
                os.chmod(cache_target_path, int(perm, 8))
'''
MK2 = "            os.makedirs(docker_storlet_path, 0o755)\n"
for b in (MK1, WRITE, MK2):
    assert original.count(b) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("    def bring_from_cache(self, obj_name, sreq, is_storlet):")
e = original.index("    def update_docker_container_from_cache(self, sreq):")
seg = original[s:e]
for a, b in (("cache_dir", "cache_root"), ("get_func", "fetch_object"), ("data_iter", "chunks"), ("fn", "target_fh")):
    seg = re.sub(r"\b%s\b" % a, b, seg)
assert "chunks" in seg and "target_fh.write" in seg
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + seg + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, WRITE, '''            # bring the object from storge
            data_iter, perm = get_func(obj_name)
            self._store_in_cache(cache_target_path, data_iter, perm,
                                 is_storlet)
''')
v2 = swap(v2, "    def bring_from_cache(self, obj_name, sreq, is_storlet):", '''    @staticmethod
    def _store_in_cache(path, data_iter, perm, is_storlet):
        # TODO(takashi): Do not directly write to target path
        with open(path, 'wb') as fn:
            for data in data_iter:
                fn.write(data)

        if not is_storlet:
            if not perm:
                perm = '0600'
            os.chmod(path, int(perm, 8))

    def bring_from_cache(self, obj_name, sreq, is_storlet):''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, MK1, "        if not os.path.exists(cache_dir):\n            os.makedirs(cache_dir, 0o700)\n")
v3 = swap(v3, MK2, "            os.makedirs(docker_storlet_path, 0o700)\n")
v3 = swap(v3, WRITE, '''            # bring the object from storge
            data_iter, perm = get_func(obj_name)

            # owner-only bits from the metadata, default 0600 (also for an unparsable value)
            try:
                mode = int(perm, 8) & 0o700 if perm else 0o600
            except ValueError:
                mode = 0o600

            # create the file with its final mode: it never exists with wider permissions
            fd = os.open(cache_target_path,
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            os.chmod(cache_target_path, mode)  # an already existing file keeps its old mode otherwise
            with os.fdopen(fd, 'wb') as fn:
                for data in data_iter:
                    fn.write(data)
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: create a cache directory for public,
regenerable thumbnails with the default 0o755, since anyone may read them and only
the service can write there."""
import os


def ensure_thumbnail_dir(path):
    if not os.path.exists(path):
        os.makedirs(path, 0o755)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
