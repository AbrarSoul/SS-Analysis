"""
Section 9 ground-truth test bundle: CASE-0249
(openstack/magnum, magnum/conductor/handlers/common/cert_manager.py
create_client_files, CVE-2024-28718, CWE-367 time-of-check/time-of-use race
with private key material).

Core vulnerable mechanism: when a cache directory is configured,
`create_client_files` writes the cluster CA certificate, the client PRIVATE KEY
and the client certificate into `<cache>/<cluster uuid>/` with
`open(path, "w+")`, writes and flushes the contents, and only THEN calls
`os.chmod(path, 0o600)` on the three files. `open` creates the file with the
process umask (typically `0o644`), so for the whole time between creation, the
write of the key and the later chmod the key file is world-readable; a local user who
lists the directory (which is `0o755` by default) can read the cluster's private key.
The upstream fix moves each `os.chmod(..., 0o600)` to right after the `open`, before
the sensitive data is written.

Measured caveat, kept in the manifest notes: the fixed order still creates the file
with the umask mode and tightens it a moment later, so a process that opens the file
in that instant (before the chmod) keeps a readable descriptor to a file that later
receives the key. The safe variant creates each file with `os.open(..., 0o600)` and
`O_EXCL`, so it never exists with wider permissions.

Sibling sites: the same open/write/chmod sequence occurs for all three files (CA,
key, certificate) inside the `if not os.path.isdir(cached_cert_dir)` branch; the
temp-file branch uses `tempfile.NamedTemporaryFile`, which is created `0o600`.

Verification: each full file is imported as a module with the `magnum.*`, `oslo_*` and
`six` imports stubbed and `CONF.cluster.temp_cache_dir` pointing at a temporary
directory; `open` inside the module is replaced by a recorder that notes the file's
real mode (`os.stat`) at every `write`. `create_client_files` runs with the process
umask `0o022`; the mode of the key file at the moment the private key is written and the
final modes are read.

Every variant is the FULL real file. `create_client_files` is called by name from
the conductor handlers, so its name and signature are kept; the renamed variant
renames locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0249"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


CACHED = '''            ca_file = open(cached_ca_file, "w+")
            ca_file.write(encodeutils.safe_decode(ca_cert.get_certificate()))
            ca_file.flush()

            key_file = open(cached_key_file, "w+")
            key_file.write(encodeutils.safe_decode(
                magnum_cert.get_decrypted_private_key()))
            key_file.flush()

            cert_file = open(cached_cert_file, "w+")
            cert_file.write(
                encodeutils.safe_decode(magnum_cert.get_certificate()))
            cert_file.flush()

            os.chmod(cached_ca_file, 0o600)
            os.chmod(cached_key_file, 0o600)
            os.chmod(cached_cert_file, 0o600)
'''
assert original.count(CACHED) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("def create_client_files(")
e = original.index("def sign_node_certificate(")
seg = original[s:e]
for a, b in (("ca_file", "ca_handle"), ("key_file", "key_handle"), ("cert_file", "cert_handle")):
    seg = re.sub(r"\b%s\b" % a, b, seg)
assert "key_handle.write" in seg and "cached_key_file" in seg
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + seg + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CACHED, '''            ca_file = _write_cached(cached_ca_file,
                                    ca_cert.get_certificate())
            key_file = _write_cached(cached_key_file,
                                     magnum_cert.get_decrypted_private_key())
            cert_file = _write_cached(cached_cert_file,
                                      magnum_cert.get_certificate())

            os.chmod(cached_ca_file, 0o600)
            os.chmod(cached_key_file, 0o600)
            os.chmod(cached_cert_file, 0o600)
''')
v2 = swap(v2, "def create_client_files(cluster, context=None):", '''def _write_cached(path, data):
    handle = open(path, "w+")
    handle.write(encodeutils.safe_decode(data))
    handle.flush()
    return handle


def create_client_files(cluster, context=None):''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, CACHED, '''            ca_file = _private_cache_file(cached_ca_file,
                                          ca_cert.get_certificate())
            key_file = _private_cache_file(
                cached_key_file, magnum_cert.get_decrypted_private_key())
            cert_file = _private_cache_file(cached_cert_file,
                                            magnum_cert.get_certificate())
''')
v3 = swap(v3, "def create_client_files(cluster, context=None):", '''def _private_cache_file(path, data):
    """Create the file with mode 0o600 from the start (never wider), then write."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    handle = os.fdopen(fd, "w+")
    handle.write(encodeutils.safe_decode(data))
    handle.flush()
    return handle


def create_client_files(cluster, context=None):''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: write a public CA certificate bundle
into a cache file with the default mode, chmod afterwards; the content is public,
so a wider mode for a moment exposes nothing."""
import os


def write_public_bundle(path, pem_text):
    with open(path, "w") as handle:
        handle.write(pem_text)
    os.chmod(path, 0o644)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
