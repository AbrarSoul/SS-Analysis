"""
Section 9 ground-truth test bundle: CASE-0230
(mlflow/mlflow, mlflow/recipes/cards/__init__.py CardTab.to_html,
CVE-2023-6709, CWE-1336 improper neutralisation of template syntax /
server-side template injection).

Core vulnerable mechanism: `CardTab.to_html` renders the tab's
caller-supplied template string with an ordinary
`jinja2.Environment(loader=BaseLoader()).from_string(self.template)`. Recipe
cards are built from templates that can come from recipe configuration or from
a shared workspace, and a full Jinja2 environment gives a template access to
Python internals, so a template such as
`{{ cycler.__init__.__globals__.os.system('...') }}` (or any
`__class__`/`__mro__`/`__globals__` walk) runs arbitrary commands in the
MLflow process when the card is rendered. The upstream fix renders with
`jinja2.sandbox.SandboxedEnvironment`, which refuses such attribute access.

Sibling sites: `CardTab.__init__` builds a plain `jinja2.Environment()` but only
calls `.parse()` (no evaluation), and `BaseCard.to_html` renders a package-owned
base template from a FileSystemLoader with tab HTML passed as data, not as
template source; neither evaluates attacker text, so `CardTab.to_html` is the
only site (the upstream fix also changes only this one).

Verification: each full file is imported as a module with `mlflow.exceptions`
stubbed (real `jinja2` 3.1 and `packaging` are used). A CardTab is built with a
template whose expression runs `os.system('touch <marker>')` through Jinja's
`cycler` object; the marker file's existence after `to_html()` shows whether the
command ran. A normal `{{ name }}` template is rendered as a control.

Every variant is the FULL real file. `CardTab.to_html` is a public method
called by name from the card classes, so its name and signature are kept; the
renamed variant renames its locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0230"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


BLOCK = '''        import jinja2

        j2_env = jinja2.Environment(loader=jinja2.BaseLoader()).from_string(self.template)
        return j2_env.render({**self._context})
'''
assert original.count(BLOCK) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BLOCK, '''        import jinja2

        compiled = jinja2.Environment(loader=jinja2.BaseLoader()).from_string(self.template)
        return compiled.render({**self._context})
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BLOCK, '''        return self._render_template(self.template, {**self._context})

    @staticmethod
    def _render_template(source: str, context: dict) -> str:
        import jinja2

        env = jinja2.Environment(loader=jinja2.BaseLoader())
        return env.from_string(source).render(context)
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same idea as upstream (a sandboxed environment) but with the immutable sandbox
# variant (it also blocks calls that modify objects), built in one place.
v3 = swap(original, BLOCK, '''        from jinja2 import BaseLoader
        from jinja2.sandbox import ImmutableSandboxedEnvironment

        env = ImmutableSandboxedEnvironment(loader=BaseLoader(), autoescape=False)
        return env.from_string(self.template).render({**self._context})
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: render a fixed, package-owned
template with data only; the template source never comes from a user."""
import jinja2

_TEMPLATE = jinja2.Environment(loader=jinja2.BaseLoader()).from_string(
    "<h1>{{ title }}</h1><p>{{ body }}</p>"
)


def render_banner(title, body):
    return _TEMPLATE.render(title=title, body=body)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
