"""
Standalone example of the same shape: skip note files whose name starts
with an underscore (a personal convention for drafts) while walking a
folder -- a content-selection filter, not a containment boundary.
"""
import os


def list_published_notes(folder):
    notes = []
    for dirpath, _dirnames, filenames in os.walk(folder, followlinks=False):
        for name in filenames:
            if name.endswith(".md") and not name.startswith("_"):
                notes.append(os.path.join(dirpath, name))
    return notes
