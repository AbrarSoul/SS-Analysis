"""
Section 9 ground-truth test bundle: CASE-0076
(Tautulli/Tautulli, CVE-2025-58761, CWE-27/CWE-78 path traversal via an
unvalidated image-format parameter).

Core vulnerable mechanism: the image-proxy endpoint builds a cache
filename via `'{}.{}'.format(img_hash, img_format)`, where `img_format`
is a caller-supplied request parameter with NO validation. Since the
resulting `fp` is then joined onto the cache directory
(`os.path.join(c_dir, fp)`) and used for actual file I/O, a caller
supplying something other than a real image extension for `img_format`
(e.g. a value containing `../` sequences) can make the resulting path
resolve outside the intended cache directory. The fix restricts
`img_format` to a small allowlist (`'png'`/`'jpg'`), silently defaulting
to `'png'` for anything else, before it's ever used to build the path.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0076"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''        if return_hash:
            return {'img_hash': img_hash}

        fp = '{}.{}'.format(img_hash, img_format)  # we want to be able to preview the thumbs
        c_dir = os.path.join(plexpy.CONFIG.CACHE_DIR, 'images')
        ffp = os.path.join(c_dir, fp)'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename img_format -> imageFormat, fp -> cacheFilename. Same exact
# unvalidated format value used to build a cache path.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''        if return_hash:
            return {'img_hash': img_hash}

        cacheFilename = '{}.{}'.format(img_hash, imageFormat)  # we want to be able to preview the thumbs
        c_dir = os.path.join(plexpy.CONFIG.CACHE_DIR, 'images')
        ffp = os.path.join(c_dir, cacheFilename)''',
)
# The parameter itself is named img_format throughout the surrounding
# (much larger) method signature/docstring/other branches -- renaming
# only the two lines directly involved in this vulnerability's own
# create-path logic (not the whole 130-line method) to isolate this
# bundle's transformation from that unrelated surrounding code, matching
# how this case's Section 9 scope was already narrowed to just this block.
renamed_source = renamed_source.replace("img_format=img_format", "img_format=imageFormat")
assert "cacheFilename = '{}.{}'.format(img_hash, imageFormat)" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting
# (early-return preserved, path pieces built with an extra intermediate
# step). Same exact unvalidated format value, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''        if return_hash:
            return {'img_hash': img_hash}

        filename_parts = [img_hash, img_format]
        fp = '.'.join(filename_parts)  # we want to be able to preview the thumbs
        c_dir = os.path.join(plexpy.CONFIG.CACHE_DIR, 'images')
        ffp = os.path.join(c_dir, fp)''',
)
assert structural_source != original
assert "filename_parts = [img_hash, img_format]" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (never let an unvalidated img_format reach
# the path-building step) but a materially different technique: a regex
# match requiring img_format to be a short, purely-alphanumeric token
# (`^[a-zA-Z0-9]{1,5}$`), raising an explicit error for anything else,
# instead of the real patch's small fixed allowlist with a silent
# fallback -- genuinely rejects path-traversal-shaped values, different
# validation strategy (reject-and-error vs. accept-and-coerce).
SAFE_SOURCE = '''import os
import re

_VALID_IMG_FORMAT_RE = re.compile(r'^[a-zA-Z0-9]{1,5}$')


def build_cache_path(img_hash, img_format, cache_dir):
    if not _VALID_IMG_FORMAT_RE.match(img_format):
        raise ValueError('Invalid image format: {}'.format(img_format))
    fp = '{}.{}'.format(img_hash, img_format)
    c_dir = os.path.join(cache_dir, 'images')
    return os.path.join(c_dir, fp)
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "_VALID_IMG_FORMAT_RE" in SAFE_SOURCE

# --- Verify the regex validator genuinely rejects a traversal-shaped
# format value ---
import re as _re
pattern = _re.compile(r'^[a-zA-Z0-9]{1,5}$')
assert pattern.match('png')
assert not pattern.match('../../../etc/passwd')
assert not pattern.match('png/../../etc')

# --- Variant 4: benign structural look-alike ---
# Same visible shape (format a hash and a format-like string into a
# filename, then os.path.join() it onto a cache directory) but this
# sibling's "format" value is always one of a FIXED tuple of internal
# constants selected by an enum-like integer, never a raw caller-supplied
# string -- so there is no way a caller could ever smuggle a traversal
# sequence into it, unlike the image-proxy endpoint's img_format
# request parameter.
BENIGN_SOURCE = '''import os

_LOG_LEVEL_EXTENSIONS = ('info', 'warn', 'error')


def build_log_cache_path(session_id, level_index, cache_dir):
    # level_index always selects from the fixed tuple above -- never a
    # raw string taken from a request, so there is no unvalidated value
    # that could ever reach the path.
    extension = _LOG_LEVEL_EXTENSIONS[level_index % len(_LOG_LEVEL_EXTENSIONS)]
    fp = '{}.{}'.format(session_id, extension)
    c_dir = os.path.join(cache_dir, 'logs')
    return os.path.join(c_dir, fp)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "img_format" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0076.")
