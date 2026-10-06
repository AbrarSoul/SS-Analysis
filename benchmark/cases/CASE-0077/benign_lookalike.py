import os
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
