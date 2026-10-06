"""
Section 9 ground-truth test bundle: CASE-0083
(adfinis/document-merge-service, CVE-2024-37301, CWE-1336 server-side
template injection).

Core vulnerable mechanism: `get_jinja_env()` builds a plain
`jinja2.Environment`, which is then used to render user-uploaded
document templates. A plain Environment exposes Python object internals
(e.g. `''.__class__.__mro__[1].__subclasses__()`), letting a template
author reach arbitrary classes and execute code on the server. The
upstream fix uses `jinja2.sandbox.SandboxedEnvironment`.

Every variant is the FULL real file with the import line and the
get_jinja_env function replaced.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0083"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.py").read_text().splitlines()) + "\n"

IMPORT = "from jinja2 import Environment, pass_context\n"
FUNC = """def get_jinja_env():
    jinja_env = Environment(extensions=settings.DOCXTEMPLATE_JINJA_EXTENSIONS)
    jinja_env.filters.update(get_jinja_filters())
    return jinja_env
"""
assert original.count(IMPORT) == 1 and original.count(FUNC) == 1
assert original.count("get_jinja_env") == 1


def build(new_func, new_import=IMPORT):
    return original.replace(IMPORT, new_import).replace(FUNC, new_func)


# --- Variant 1: renamed vulnerable variant ---
renamed = build("""def build_template_environment():
    template_env = Environment(extensions=settings.DOCXTEMPLATE_JINJA_EXTENSIONS)
    template_env.filters.update(get_jinja_filters())
    return template_env
""")
assert "get_jinja_env" not in renamed and "Environment(extensions" in renamed
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.py").write_text(build("""def get_jinja_env():
    env_options = {"extensions": settings.DOCXTEMPLATE_JINJA_EXTENSIONS}
    jinja_env = Environment(**env_options)
    for name, func in get_jinja_filters().items():
        jinja_env.filters[name] = func
    return jinja_env
"""))

# --- Variant 3: transformed safe variant ---
# ImmutableSandboxedEnvironment (stricter than the upstream
# SandboxedEnvironment: additionally blocks mutation of lists/dicts/sets).
(CASE_DIR / "variant_safe_01.py").write_text(build(
    """def get_jinja_env():
    jinja_env = ImmutableSandboxedEnvironment(
        extensions=settings.DOCXTEMPLATE_JINJA_EXTENSIONS
    )
    jinja_env.filters.update(get_jinja_filters())
    return jinja_env
""",
    "from jinja2 import pass_context\nfrom jinja2.sandbox import ImmutableSandboxedEnvironment\n",
))

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.py").write_text('''from jinja2 import Environment


def render_status_banner(service_name, uptime_seconds):
    """Uses a plain Environment, but the template text is a fixed
    developer-written constant; callers supply only data values, never
    template source, so no attacker-controlled template is ever compiled."""
    env = Environment(autoescape=True)
    template = env.from_string("{{ name }} has been up for {{ seconds }}s")
    return template.render(name=service_name, seconds=uptime_seconds)
''')
print("Wrote 4 new samples for CASE-0083.")
