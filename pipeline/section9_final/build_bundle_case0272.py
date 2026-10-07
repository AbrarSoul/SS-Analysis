"""
Section 9 ground-truth test bundle: CASE-0272
(pyload/pyload, src/pyload/webui/app/__init__.py App._configure_session,
CVE-2023-0055, CWE-319/CWE-614 cleartext transmission / sensitive cookie
without the Secure attribute).

Core vulnerable mechanism: `_configure_session` sets up Flask-Session's
cookie (`SESSION_COOKIE_NAME`, lifetime, etc.) but never sets
`SESSION_COOKIE_SECURE`, so Flask's own default (`False`) applies -- the
browser will send the `pyload_session` cookie over a PLAIN HTTP connection
just as readily as over HTTPS, even when the deployment has SSL/TLS
enabled (`webui.use_ssl` in pyload's own config). A network attacker on the
same LAN/Wi-Fi, a malicious proxy, or anyone able to observe unencrypted
traffic (e.g. if any page on the same origin is ever loaded over plain
HTTP, intentionally or via a downgrade) can read the session cookie off
the wire in cleartext and reuse it to fully hijack an authenticated
pyload session. The upstream fix sets `SESSION_COOKIE_SECURE` from the
same `PYLOAD_API` config the rest of the method already reads:
`app.config["SESSION_COOKIE_SECURE"] =
app.config["PYLOAD_API"].get_config_value("webui", "use_ssl")` -- so when
the deployment is configured for SSL, the browser is instructed (via the
Secure cookie attribute) to withhold the cookie from any non-HTTPS
request.

Sibling sites: `_configure_session` is the only place in the file that
sets Flask-Session cookie options; there is one call site to fix.

Verification: each full file's `App._configure_session` classmethod is
called as real, unmodified code against a REAL `flask.Flask` app instance
(`flask` is a real dependency already used throughout pyload's webui) with
a minimal stand-in `PYLOAD_API` object exposing `get_cachedir()` and
`get_config_value("webui", "use_ssl")` (controllable: True or False, the
one piece of state this method actually reads). After calling
`_configure_session(app)`, `app.config.get("SESSION_COOKIE_SECURE")` is
inspected for both an SSL-enabled and an SSL-disabled deployment.

Every variant is the FULL real file. `_configure_session` is called by
name from `App.__new__` (`cls._configure_session(app)`) during Flask app
construction, so its name and `(cls, app)` signature are kept; the
renamed variant renames its own locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0272"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


METHOD = '''    @classmethod
    def _configure_session(cls, app):
        tempdir = app.config["PYLOAD_API"].get_cachedir()
        cache_path = os.path.join(tempdir, "flask")
        os.makedirs(cache_path, exist_ok=True)

        app.config["SESSION_FILE_DIR"] = cache_path
        app.config["SESSION_TYPE"] = "filesystem"
        app.config["SESSION_COOKIE_NAME"] = "pyload_session"
        app.config["SESSION_PERMANENT"] = False

        session_lifetime = max(app.config["PYLOAD_API"].get_config_value("webui", "session_lifetime"), 1) * 60
        app.config["PERMANENT_SESSION_LIFETIME"] = session_lifetime'''
assert original.count(METHOD) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, METHOD, '''    @classmethod
    def _configure_session(cls, flask_app):
        tmpdir = flask_app.config["PYLOAD_API"].get_cachedir()
        session_cache_path = os.path.join(tmpdir, "flask")
        os.makedirs(session_cache_path, exist_ok=True)

        flask_app.config["SESSION_FILE_DIR"] = session_cache_path
        flask_app.config["SESSION_TYPE"] = "filesystem"
        flask_app.config["SESSION_COOKIE_NAME"] = "pyload_session"
        flask_app.config["SESSION_PERMANENT"] = False

        lifetime_seconds = max(flask_app.config["PYLOAD_API"].get_config_value("webui", "session_lifetime"), 1) * 60
        flask_app.config["PERMANENT_SESSION_LIFETIME"] = lifetime_seconds''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, METHOD, '''    @classmethod
    def _session_cache_path(cls, app):
        tempdir = app.config["PYLOAD_API"].get_cachedir()
        cache_path = os.path.join(tempdir, "flask")
        os.makedirs(cache_path, exist_ok=True)
        return cache_path

    @classmethod
    def _configure_session(cls, app):
        app.config["SESSION_FILE_DIR"] = cls._session_cache_path(app)
        app.config["SESSION_TYPE"] = "filesystem"
        app.config["SESSION_COOKIE_NAME"] = "pyload_session"
        app.config["SESSION_PERMANENT"] = False

        session_lifetime = max(app.config["PYLOAD_API"].get_config_value("webui", "session_lifetime"), 1) * 60
        app.config["PERMANENT_SESSION_LIFETIME"] = session_lifetime''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (SESSION_COOKIE_SECURE mirrors the webui's
# own use_ssl setting) but computed once into a local before assignment,
# instead of upstream's inline chained attribute access on the same line.
v3 = swap(original, METHOD, '''    @classmethod
    def _configure_session(cls, app):
        tempdir = app.config["PYLOAD_API"].get_cachedir()
        cache_path = os.path.join(tempdir, "flask")
        os.makedirs(cache_path, exist_ok=True)

        use_ssl = bool(app.config["PYLOAD_API"].get_config_value("webui", "use_ssl"))

        app.config["SESSION_FILE_DIR"] = cache_path
        app.config["SESSION_TYPE"] = "filesystem"
        app.config["SESSION_COOKIE_NAME"] = "pyload_session"
        app.config["SESSION_COOKIE_SECURE"] = use_ssl
        app.config["SESSION_PERMANENT"] = False

        session_lifetime = max(app.config["PYLOAD_API"].get_config_value("webui", "session_lifetime"), 1) * 60
        app.config["PERMANENT_SESSION_LIFETIME"] = session_lifetime''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""
Standalone example of the same shape: derive a display setting (whether to
show a "beta" badge in the UI) from a config flag, computed once and
assigned to a Flask app.config key -- purely cosmetic, never a security
boundary, unlike a cookie's Secure attribute.
"""


def configure_ui_badges(app, feature_config):
    show_beta_badge = bool(feature_config.get_config_value("ui", "beta_features"))
    app.config["SHOW_BETA_BADGE"] = show_beta_badge
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
