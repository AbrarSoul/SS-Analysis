"""
Standalone example of the same shape: a recursive directory sizer that
recurses on real, finite filesystem trees from a caller-supplied root
(no attacker-controlled link graph, no cycles since symlinks are skipped),
so unbounded depth is not an input-driven risk.
"""
import os


def tree_size(path):
    total = 0
    for entry in os.scandir(path):
        if entry.is_symlink():
            continue
        if entry.is_dir():
            total += tree_size(entry.path)
        else:
            total += entry.stat().st_size
    return total
