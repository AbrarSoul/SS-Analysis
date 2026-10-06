"""
Section 9 ground-truth test bundle: CASE-0077
(Tencent/NeuralNLP-NeuralClassifier, CVE-2025-13708, CWE-502
deserialization of untrusted data via unsafe torch.load()).

Core vulnerable mechanism: `_load_checkpoint()` calls `torch.load(file_name)`
with no `weights_only` argument. By default, `torch.load()` unpickles the
ENTIRE checkpoint object using Python's standard `pickle` protocol, which
can execute arbitrary code embedded in the file via a crafted
`__reduce__`/`__setstate__` on any object the pickle stream references --
this is not a tensor-format quirk, it's the same well-known "pickle RCE"
class as `pickle.load()` on data from an untrusted source. Since
checkpoint files are commonly downloaded from third-party model hubs or
shared between users, loading one is effectively arbitrary code execution
on an untrusted file. The fix adds `weights_only=True`, which restricts
deserialization to a safe, tensor-only unpickler that cannot execute
arbitrary code.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0077"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    def _load_checkpoint(file_name, model, use_cuda):
        if use_cuda:
            checkpoint = torch.load(file_name)
        else:
            checkpoint = torch.load(file_name, map_location=lambda storage, loc: storage)
        model.load_state_dict(checkpoint["state_dict"])'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename _load_checkpoint -> load_model_weights, file_name ->
# checkpoint_path. Same exact unsafe torch.load() without weights_only.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def load_model_weights(checkpoint_path, model, use_cuda):
        if use_cuda:
            checkpoint = torch.load(checkpoint_path)
        else:
            checkpoint = torch.load(checkpoint_path, map_location=lambda storage, loc: storage)
        model.load_state_dict(checkpoint["state_dict"])''',
)
assert "def load_model_weights(checkpoint_path, model, use_cuda):" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting
# (map_location computed unconditionally, torch.load called once). Same
# exact unsafe deserialization, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def _load_checkpoint(file_name, model, use_cuda):
        map_location = None if use_cuda else (lambda storage, loc: storage)
        checkpoint = torch.load(file_name, map_location=map_location)
        model.load_state_dict(checkpoint["state_dict"])''',
)
assert structural_source != original
assert "map_location = None if use_cuda else" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (prevent arbitrary code execution from a
# malicious checkpoint's pickle stream) but a materially different
# technique: a custom restricted Unpickler that only allows a small
# explicit allowlist of safe classes (torch tensor/storage types and
# basic builtins), raising for anything else -- rather than the real
# patch's built-in `weights_only=True` flag. Genuinely blocks arbitrary
# class instantiation during unpickling, different implementation layer.
SAFE_SOURCE = '''import io
import pickle

_ALLOWED_MODULES_CLASSES = {
    ("torch", "Tensor"),
    ("torch._utils", "_rebuild_tensor_v2"),
    ("collections", "OrderedDict"),
    ("builtins", "dict"),
    ("builtins", "list"),
}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in _ALLOWED_MODULES_CLASSES:
            raise pickle.UnpicklingError(
                "Refusing to unpickle disallowed class: {}.{}".format(module, name)
            )
        return super().find_class(module, name)


def safe_torch_load(file_name):
    with open(file_name, "rb") as f:
        return RestrictedUnpickler(io.BytesIO(f.read())).load()


def _load_checkpoint(file_name, model, use_cuda):
    checkpoint = safe_torch_load(file_name)
    model.load_state_dict(checkpoint["state_dict"])
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "RestrictedUnpickler" in SAFE_SOURCE

# --- Verify the restricted unpickler genuinely refuses to instantiate a
# disallowed class (simulating what a malicious checkpoint's __reduce__
# payload would attempt) ---
import pickle as _pickle
import io as _io


class _DisallowedClass:
    def __reduce__(self):
        return (str, ("this should never be constructed via find_class",))


_ALLOWED_MODULES_CLASSES = {("builtins", "dict")}


class _TestRestrictedUnpickler(_pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) not in _ALLOWED_MODULES_CLASSES:
            raise _pickle.UnpicklingError("blocked: {}.{}".format(module, name))
        return super().find_class(module, name)


payload = _pickle.dumps({"safe": "value"})
result = _TestRestrictedUnpickler(_io.BytesIO(payload)).load()
assert result == {"safe": "value"}, "restricted unpickler should still allow safe dict payloads"

malicious_payload = _pickle.dumps(("os", "system"))  # a tuple naming a dangerous class, not itself dangerous, but demonstrates find_class is consulted
try:
    _TestRestrictedUnpickler(_io.BytesIO(_pickle.dumps(complex(1, 2)))).load()
    raise AssertionError("expected UnpicklingError for a disallowed class (complex)")
except _pickle.UnpicklingError:
    pass  # expected: complex is not in the allowlist

# --- Variant 4: benign structural look-alike ---
# Same visible shape (torch.load(some_path) with no weights_only flag)
# but this sibling only ever loads a FIXED checkpoint file bundled inside
# the package's own installed data directory at build time -- never a
# path supplied by a user, downloaded from a model hub, or otherwise
# externally influenced -- so there is no untrusted pickle stream this
# could ever be asked to deserialize, unlike _load_checkpoint()'s
# caller-supplied file_name.
BENIGN_SOURCE = '''import os
import torch

_BUNDLED_DEFAULT_EMBEDDINGS = os.path.join(
    os.path.dirname(__file__), "data", "default_embeddings.pt"
)


def load_bundled_default_embeddings():
    """Loads only this package's own bundled embeddings file, shipped
    inside the installed package itself -- never a path or file supplied
    by a user or downloaded at runtime, so there is no untrusted pickle
    stream reaching torch.load() here."""
    return torch.load(_BUNDLED_DEFAULT_EMBEDDINGS)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "file_name" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0077.")
