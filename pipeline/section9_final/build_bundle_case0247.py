"""
Section 9 ground-truth test bundle: CASE-0247
(openstack/glance, glance/common/scripts/image_import/main.py import_image,
CVE-2014-9684, CWE-399 resource management: orphaned image data).

Core vulnerable mechanism: the import task creates an image record, uploads the
data with `set_image_data(original_image, uri, None)` (the bytes now sit in the
storage backend) and only afterwards re-reads the record to make it active.
If the image was deleted (or otherwise left the `saving` state) while the data was
being fetched, `import_image` raises `exception.Conflict` (or the `image_repo.get`
raises `NotFound`) and returns, but nothing removes the data it already wrote:
the bytes stay in the backend with no image record pointing at them, so a user
can fill the store with unreachable data by creating and deleting import tasks.
The upstream fix wraps the tail in `try`/`except (Conflict, NotFound)` and, inside
`excutils.save_and_reraise_exception()`, deletes every location of the original
image with `store_utils.delete_image_location_from_backend`.

Measured caveat, kept in the manifest notes: the upstream cleanup only runs for
`Conflict` and `NotFound`; any other failure after the data is stored (for example an
error from `image_repo.save`) still leaves the uploaded data orphaned. The safe variant
cleans up on any exception raised after the data was stored.

Sibling sites: `import_image` is the only place in the file that stores data and then
finalises the record.

Verification: each full file is imported as a module with the `glance.*` and
`oslo.utils` imports stubbed (a faithful minimal `save_and_reraise_exception`);
`create_image` and `set_image_data` are replaced after import by stand-ins that
return an image object with two stored locations. `import_image` is run against
fake image repositories: (a) the image was deleted meanwhile (`get` returns status
`deleted`), (b) `get` raises NotFound, (c) `save` raises an unexpected error, (d) the
normal case; the stand-in `store_utils.delete_image_location_from_backend` records the
deleted locations.

Every variant is the FULL real file. `import_image` is called by name from
`run`, so its name and signature are kept; the renamed variant renames locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0247"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


TAIL = '''    image_id = original_image.image_id
    new_image = image_repo.get(image_id)
    if new_image.status in ['saving']:
        new_image.status = 'active'
        new_image.size = original_image.size
        new_image.virtual_size = original_image.virtual_size
        new_image.checksum = original_image.checksum
    else:
        msg = _("The Image %(image_id)s object being created by this task "
                "%(task_id)s, is no longer in valid status for further "
                "processing.") % {"image_id": new_image.image_id,
                                  "task_id": task_id}
        raise exception.Conflict(msg)
    image_repo.save(new_image)

    return image_id
'''
assert original.count(TAIL) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("def import_image(")
e = original.index("def create_image(")
seg = original[s:e]
import re
seg = re.sub(r"\boriginal_image\b", "uploaded", seg)
seg = re.sub(r"\bnew_image\b", "current_image", seg)
seg = re.sub(r"\bmsg\b", "problem", seg)
assert "uploaded.image_id" in seg and "current_image.status" in seg
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + seg + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, TAIL, '''    image_id = original_image.image_id
    new_image = image_repo.get(image_id)
    _activate(new_image, original_image, task_id)
    image_repo.save(new_image)

    return image_id


def _activate(new_image, original_image, task_id):
    if new_image.status in ['saving']:
        new_image.status = 'active'
        new_image.size = original_image.size
        new_image.virtual_size = original_image.virtual_size
        new_image.checksum = original_image.checksum
    else:
        msg = _("The Image %(image_id)s object being created by this task "
                "%(task_id)s, is no longer in valid status for further "
                "processing.") % {"image_id": new_image.image_id,
                                  "task_id": task_id}
        raise exception.Conflict(msg)
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "from glance.common.scripts import utils as script_utils\n",
          "from glance.common.scripts import utils as script_utils\nfrom glance.common import store_utils\n")
v3 = swap(v3, TAIL, '''    image_id = original_image.image_id
    try:
        new_image = image_repo.get(image_id)
        if new_image.status in ['saving']:
            new_image.status = 'active'
            new_image.size = original_image.size
            new_image.virtual_size = original_image.virtual_size
            new_image.checksum = original_image.checksum
        else:
            msg = _("The Image %(image_id)s object being created by this task "
                    "%(task_id)s, is no longer in valid status for further "
                    "processing.") % {"image_id": new_image.image_id,
                                      "task_id": task_id}
            raise exception.Conflict(msg)
        image_repo.save(new_image)
    except Exception:
        # Whatever went wrong after the data was stored, do not leave it orphaned in the backend.
        with excutils.save_and_reraise_exception():
            _discard_stored_data(original_image)

    return image_id


def _discard_stored_data(original_image):
    for location in (original_image.locations or []):
        store_utils.delete_image_location_from_backend(
            original_image.context, original_image.image_id, location)
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: upload, then finalise, where the
temporary upload is removed in a finally block on every path."""
import os


def publish(tmp_path, final_path, validate):
    try:
        validate(tmp_path)
        os.replace(tmp_path, final_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
