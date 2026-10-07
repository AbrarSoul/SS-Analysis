"""
Section 9 ground-truth test bundle: CASE-0250
(openstack/nova, nova/virt/libvirt/utils.py remove_logical_volumes,
CVE-2012-5625, CWE-200 information disclosure through unerased volume data).

Core vulnerable mechanism: LVM-backed instances keep their disks (root, ephemeral, swap)
on logical volumes carved out of a shared volume group. When an instance is destroyed,
`remove_logical_volumes` only runs `lvremove -f <paths>`. The blocks go back to the
volume group with the old tenant's data still on them, and the next instance whose
logical volume is allocated over the same extents can read them (an LV is
not zero-filled on creation). The upstream fix adds `logical_volume_size` and
`clear_logical_volume` and calls the latter for every path before `lvremove`: it
overwrites the volume with zeros using `dd` (O_DIRECT for the first, large block
size).

Measured caveat, kept in the manifest notes: the upstream `clear_logical_volume` uses `/`
where Python 2 integer division was intended (`zero_blocks = remaining_bytes / bs`,
`bs /= 1024`); under Python 3 the same code yields float block counts and seeks
(`count=5.0`) that dd rejects, so the harness emulates Python 2 by turning ` / ` and
` /= ` into floor division in the harness copy of the two functions only (the shipped
files are untouched). The safe variant uses `divmod`, which behaves the same on both.

Sibling sites: `remove_logical_volumes` is the only place in the file that deletes logical
volumes.

Verification: `logical_volume_size`, `clear_logical_volume` (fixed forms) and
`remove_logical_volumes` are extracted from each full file with a stand-in `execute`/
`utils.execute` that records every command and answers the `lvs` size query (5 MiB + 300
bytes). The recorded `dd` commands are replayed onto a byte array to see whether the whole
volume ends up zeroed.

Every variant is the FULL real file. `remove_logical_volumes` is called by name from the
libvirt driver, so its name and `*paths` signature are kept; the renamed variant renames
locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0250"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


RM = '''def remove_logical_volumes(*paths):
    """Remove one or more logical volume."""
    if paths:
        lvremove = ('lvremove', '-f') + paths
        execute(*lvremove, attempts=3, run_as_root=True)
'''
assert original.count(RM) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, RM, '''def remove_logical_volumes(*paths):
    """Remove one or more logical volume."""
    if paths:
        removal_cmd = ('lvremove', '-f') + paths
        execute(*removal_cmd, attempts=3, run_as_root=True)
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, RM, '''def _lvremove(paths):
    lvremove = ('lvremove', '-f') + paths
    execute(*lvremove, attempts=3, run_as_root=True)


def remove_logical_volumes(*paths):
    """Remove one or more logical volume."""
    if paths:
        _lvremove(paths)
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, RM, '''def logical_volume_size(path):
    """Get logical volume size in bytes."""
    out, _err = execute('lvs', '-o', 'lv_size', '--noheadings', '--units',
                        'b', '--nosuffix', path, run_as_root=True)
    return int(out)


def clear_logical_volume(path):
    """Overwrite the whole logical volume with zeros (integer arithmetic only)."""
    size = logical_volume_size(path)
    bs = 1024 * 1024
    full_blocks, tail = divmod(size, bs)
    if full_blocks:
        execute('dd', 'bs=%d' % bs, 'if=/dev/zero', 'of=%s' % path,
                'count=%d' % full_blocks, 'oflag=direct', run_as_root=True)
    if tail:
        execute('dd', 'bs=1', 'if=/dev/zero', 'of=%s' % path,
                'seek=%d' % (full_blocks * bs), 'count=%d' % tail,
                run_as_root=True)


def remove_logical_volumes(*paths):
    """Remove one or more logical volume."""
    for path in paths:
        clear_logical_volume(path)

    if paths:
        lvremove = ('lvremove', '-f') + paths
        execute(*lvremove, attempts=3, run_as_root=True)
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: remove a scratch logical volume that
only ever held a public, regenerable build cache, so nothing needs to be wiped
before the extents are reused."""


def remove_scratch_volume(execute, path):
    execute('lvremove', '-f', path, attempts=3, run_as_root=True)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
