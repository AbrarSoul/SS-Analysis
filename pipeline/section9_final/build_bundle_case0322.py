r"""
Section 9 ground-truth test bundle: CASE-0322
(voila-dashboards/voila, voila/app.py Voila.start, CVE-2024-30265,
CWE-73 external control of file name or path).

Core vulnerable mechanism: `Voila.start` builds the Tornado
`Application(...)` with `static_path='/'`. Tornado registers a DEFAULT
route `/static/(.*)` (`StaticFileHandler`) whenever `static_path` is set, and
here the static root is the filesystem root, so `GET /static/etc/passwd` (or
any absolute path of a file readable by the Voila process, e.g. SSH keys
or notebooks with credentials) returns the file to any unauthenticated
client (arbitrary file read). The upstream fix simply removes the
`static_path='/'` setting.

Sibling sites: the legitimate static routes (`/voila/static/...`,
`/voila/templates/...`) are added explicitly further down `start` with their
own restricted directories and are unaffected.

Verification (REAL tornado): the application construction of `start`
(from the `# default server_url to base_url` comment through
`self.app.settings.update(...)`) is sliced from each full file and exec'd
against real tornado with a stub `self`; the resulting Application is
served by a real `HTTPServer` on an ephemeral port and
`GET /static/<absolute path of a temp file containing TOP-SECRET-STATIC>`
is requested with `urllib`. Vulnerable variants answer 200 with the secret;
patched/safe answer 404; the application's own settings (`server_root_dir`,
`base_url`) are identical in all files.

Every variant is the FULL real file; `start` is the Application entry point
and keeps its name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0322"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


def rename_lines(text, pairs):
    out = []
    for line in text.split("\n"):
        if not line.lstrip().startswith("#"):
            for old, new in pairs:
                line = re.sub(r"(?<![\w.'\"])%s(?![\w'\"=])" % old, new, line)
        out.append(line)
    return "\n".join(out)


A = original.index('        jenv_opt = {"autoescape": True}')
B = original.index("        self.app = tornado.web.Application(")
REG = original[A:B]
REGION_END = original.index("        self.app.settings.update(self.tornado_settings)")

# --- Variant 1: renamed vulnerable variant (locals of start renamed; keyword names stay) ---
seg = original[A:REGION_END]
seg1 = rename_lines(seg, [("jenv_opt", "env_options"), ("env", "template_env"), ("nbui", "translation"),
                          ("read_config_path", "config_dirs")])
assert "voila_jinja2_env=template_env" in seg1 and "read_config_path=config_dirs" in seg1
assert "static_path='/'" in seg1
v1 = original[:A] + seg1 + original[REGION_END:]
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (Application settings built in a dict first) ---
APP = original[B:original.index("        )\n", B) + len("        )\n")]
assert "static_path='/'" in APP and APP.count("\n") == 14, APP.count("\n")
settings_block = ("        app_settings = dict(\n" + "".join(APP.split("\n", 1)[1:])[: -len("        )\n")] + "        )\n"
                  "        self.app = tornado.web.Application(**app_settings)\n")
v2 = swap(original, APP, settings_block)
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the same dict-first construction) ---
PB = patched.index("        self.app = tornado.web.Application(")
PAPP = patched[PB:patched.index("        )\n", PB) + len("        )\n")]
assert "static_path" not in PAPP
p_block = ("        app_settings = dict(\n" + "".join(PAPP.split("\n", 1)[1:])[: -len("        )\n")] + "        )\n"
           "        self.app = tornado.web.Application(**app_settings)\n")
v3 = swap(patched, PAPP, p_block)
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''import os

import tornado.web

HERE = os.path.dirname(os.path.abspath(__file__))


def make_docs_app():
    """Documentation server: static files come from ONE bundled directory, not the filesystem root.

    tornado's StaticFileHandler refuses to serve anything outside static_path
    (path traversal is rejected), so only files shipped with the docs are reachable.
    """
    return tornado.web.Application(
        static_path=os.path.join(HERE, 'docs_static'),
        static_url_prefix='/docs-static/',
    )
''')
