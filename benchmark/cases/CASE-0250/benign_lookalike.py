"""Standalone example of the same shape: remove a scratch logical volume that
only ever held a public, regenerable build cache, so nothing needs to be wiped
before the extents are reused."""


def remove_scratch_volume(execute, path):
    execute('lvremove', '-f', path, attempts=3, run_as_root=True)
