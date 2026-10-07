"""Standalone example of the same shape as the fixed socket-path check
(create a dedicated directory with restrictive permissions if missing, verify
an existing path's permissions before reuse) but for a purely local,
non-sensitive scratch directory: there is nothing confidential or
authoritative behind it, so even skipping the check costs nothing."""
import os


_SCRATCH_DIR = "/var/tmp/example-app/render-cache"


def ensure_render_cache_dir():
    if not os.path.isdir(_SCRATCH_DIR):
        os.makedirs(_SCRATCH_DIR, 0o700)
    elif os.stat(_SCRATCH_DIR).st_mode & 0o777 != 0o700:
        # Hygiene only: tighten permissions on a plain thumbnail cache that
        # holds no secrets and is fully regenerable from public inputs.
        os.chmod(_SCRATCH_DIR, 0o700)
