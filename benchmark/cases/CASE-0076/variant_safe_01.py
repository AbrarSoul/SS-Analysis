import os
import re

_VALID_IMG_FORMAT_RE = re.compile(r'^[a-zA-Z0-9]{1,5}$')


def build_cache_path(img_hash, img_format, cache_dir):
    if not _VALID_IMG_FORMAT_RE.match(img_format):
        raise ValueError('Invalid image format: {}'.format(img_format))
    fp = '{}.{}'.format(img_hash, img_format)
    c_dir = os.path.join(cache_dir, 'images')
    return os.path.join(c_dir, fp)
