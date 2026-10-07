"""
Section 9 ground-truth test bundle: CASE-0248
(openstack/glance_store, glance_store/_drivers/s3.py Store.get,
CVE-2024-1141, CWE-532 insertion of sensitive information into a log file;
NVD also lists CWE-779).

Core vulnerable mechanism: the S3 driver's `get` and `delete` methods write a
DEBUG line for every object they touch that includes the storage account's
ACCESS KEY: `"Retrieved image object from S3 using s3_host=%(s3_host)s,
access_key=%(accesskey)s, bucket=..."` with `'accesskey': loc.accesskey`, and the
same in `delete`. With debug logging on (common while troubleshooting), the S3
credentials that authorise every image read and delete land in the service logs, which
are readable by operators, log shippers and anyone who is given a log excerpt. The
upstream fix drops the access key from both messages.

Sibling sites: `get` (the auto-located target) and `delete` carry the identical
logging of `loc.accesskey`; the upstream patch changes both hunks, so the safe
variant fixes both and the vulnerable variants leave both. The `add` path's debug line
(`Adding image object to S3 using (s3_host=..., bucket=..., key=...)`) already
omits credentials.

Verification: `Store.get` and `Store.delete` are extracted verbatim from each full file
into a class whose helpers (`_operation_set`, `_object_exists`, the S3 client) are
stand-ins; the module's `LOG` is a REAL `logging` logger at DEBUG with a handler that
captures every record. The store location carries the access key `AKIAIOSFODNN7EXAMPLE`; `get`
(consumed once) and `delete` are called and the captured log text is searched for the key.

Every variant is the FULL real file. `get` and `delete` are the glance_store driver
interface, so their names and signatures are kept; the renamed variant renames
locals of `get`.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0248"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


GET_LOG = '''        LOG.debug("Retrieved image object from S3 using s3_host=%(s3_host)s, "
                  "access_key=%(accesskey)s, bucket=%(bucket)s, "
                  "key=%(key)s)",
                  {'s3_host': loc.s3serviceurl, 'accesskey': loc.accesskey,
                   'bucket': bucket, 'key': key})
'''
DEL_LOG = '''        LOG.debug("Deleting image object from S3 using s3_host=%(s3_host)s, "
                  "accesskey=%(accesskey)s, bucket=%(bucket)s, key=%(key)s)",
                  {'s3_host': loc.s3serviceurl, 'accesskey': loc.accesskey,
                   'bucket': bucket, 'key': key})
'''
assert original.count(GET_LOG) == 1 and original.count(DEL_LOG) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("    def get(self, location, offset=0, chunk_size=None, context=None):")
e = original.index("\n    def ", s + 10)
seg = original[s:e]
seg = re.sub(r"\bloc\b", "store_loc", seg)
seg = re.sub(r"\bcs\b", "chunk", seg)
assert "store_loc.accesskey" in seg and "chunk" in seg
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + seg + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, GET_LOG, "        self._log_object_access('Retrieved', loc, bucket, key)\n")
v2 = swap(v2, DEL_LOG, "        self._log_object_access('Deleting', loc, bucket, key)\n")
v2 = swap(v2, "    def get(self, location, offset=0, chunk_size=None, context=None):", '''    @staticmethod
    def _log_object_access(action, loc, bucket, key):
        LOG.debug("%(action)s image object from S3 using s3_host=%(s3_host)s, "
                  "access_key=%(accesskey)s, bucket=%(bucket)s, key=%(key)s)",
                  {'action': action, 's3_host': loc.s3serviceurl,
                   'accesskey': loc.accesskey, 'bucket': bucket, 'key': key})

    def get(self, location, offset=0, chunk_size=None, context=None):''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, GET_LOG, "        self._log_object_access('Retrieved', loc, bucket, key)\n")
v3 = swap(v3, DEL_LOG, "        self._log_object_access('Deleting', loc, bucket, key)\n")
v3 = swap(v3, "    def get(self, location, offset=0, chunk_size=None, context=None):", '''    @staticmethod
    def _log_object_access(action, loc, bucket, key):
        # never log credentials: host, bucket and key are enough to trace a request
        LOG.debug("%(action)s image object from S3 using s3_host=%(s3_host)s, "
                  "bucket=%(bucket)s, key=%(key)s)",
                  {'action': action, 's3_host': loc.s3serviceurl,
                   'bucket': bucket, 'key': key})

    def get(self, location, offset=0, chunk_size=None, context=None):''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: a debug line naming the operation, the
host, the bucket and the key, with no credentials (the access key stays in the
client object)."""
import logging

LOG = logging.getLogger(__name__)


def log_get(s3_host, bucket, key):
    LOG.debug("Retrieved image object from S3 using s3_host=%(s3_host)s, "
              "bucket=%(bucket)s, key=%(key)s)",
              {'s3_host': s3_host, 'bucket': bucket, 'key': key})
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
