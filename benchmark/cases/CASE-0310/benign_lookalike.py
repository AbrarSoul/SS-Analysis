"""Plugin loader example: routes a dotted module name to a plugin namespace."""
from __future__ import annotations

FIRST_PARTY_NAMESPACES = ("acme_reports", "acme_export", "acme_import")


def plugin_namespace(module_name: str) -> str | None:
    """Return the first-party namespace a dotted plugin module belongs to.

    The name comes from the application's own plugin manifest (never from
    untrusted input) and is only used to choose a settings section, so an
    exact-match comparison against the namespaces is what is wanted here: a
    sub-package such as `acme_reports.pdf` maps to `acme_reports`, and anything
    else returns None and is loaded with default settings.
    """
    if not module_name:
        return None
    for namespace in FIRST_PARTY_NAMESPACES:
        if module_name == namespace or module_name.startswith(namespace + "."):
            return namespace
    return None


def all_components_valid(module_name: str) -> bool:
    return all(part.isidentifier() for part in module_name.split("."))
