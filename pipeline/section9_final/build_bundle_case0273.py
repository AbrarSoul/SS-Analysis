"""
Section 9 ground-truth test bundle: CASE-0273
(pyload/pyload, src/pyload/webui/app/__init__.py App._configure_handlers,
CVE-2023-0057, CWE-1021 improper restriction of rendered UI layers /
clickjacking).

Core vulnerable mechanism: `_configure_handlers` registers Flask's error
handlers but never adds any response header restricting whether the
pyload webui may be embedded in a third-party `<iframe>`. Without
`X-Frame-Options` (or a `Content-Security-Policy: frame-ancestors`), a
browser will happily render the webui inside a frame on an attacker's
page; an attacker overlays invisible/transparent bait content on top of
real webui controls (e.g. "delete downloads," "add a malicious download
URL," account settings) and tricks a logged-in user into clicking through
to execute those actions inside their own authenticated session --
clickjacking. The upstream fix registers an `@app.after_request` hook
(`deny_iframe`) that sets `X-Frame-Options: DENY` on every response, so
browsers refuse to render the app in a frame at all, from any origin.

Sibling sites: `_configure_handlers` is the only place in the file that
registers global response hooks/headers; there is one call site to fix.

Verification: each full file's classmethods from `_configure_handlers`
through the one right before `_configure_templating` (a stable anchor
either side of the target, capturing any helper a variant adds) are
extracted verbatim and wrapped in a throwaway class so `cls`/classmethod
binding works naturally, then run against a REAL `flask.Flask` app and
REAL `flask.Flask.test_client()`: `_configure_handlers(app)` is called to
register the hook, then a request is made through the real Flask
dispatch/response pipeline and the response's `X-Frame-Options` header is
inspected.

Every variant is the FULL real file. `_configure_handlers` is called by
name from `App.__new__` (`cls._configure_handlers(app)`), so its name and
`(cls, app)` signature are kept; the renamed variant renames its own
locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0273"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


METHOD = '''    @classmethod
    def _configure_handlers(cls, app):
        """
        Register error handlers.
        """
        for exc, fn in cls.FLASK_ERROR_HANDLERS:
            app.register_error_handler(exc, fn)'''
assert original.count(METHOD) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, METHOD, '''    @classmethod
    def _configure_handlers(cls, flask_app):
        """
        Register error handlers.
        """
        for exception_cls, handler_fn in cls.FLASK_ERROR_HANDLERS:
            flask_app.register_error_handler(exception_cls, handler_fn)''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, METHOD, '''    @classmethod
    def _register_error_handlers(cls, app):
        for exc, fn in cls.FLASK_ERROR_HANDLERS:
            app.register_error_handler(exc, fn)

    @classmethod
    def _configure_handlers(cls, app):
        """
        Register error handlers.
        """
        cls._register_error_handlers(app)''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (X-Frame-Options: DENY on every response)
# but registered as a module-level, named function passed to
# app.after_request(...), instead of upstream's nested closure defined
# with @app.after_request as a decorator.
v3 = swap(original, METHOD, '''    @classmethod
    def _configure_handlers(cls, app):
        """
        Register app handlers.
        """
        for exc, fn in cls.FLASK_ERROR_HANDLERS:
            app.register_error_handler(exc, fn)

        app.after_request(_set_frame_deny_header)''')
v3 = swap(v3, "#: flask app singleton?\nclass App:", '''def _set_frame_deny_header(response):
    response.headers["X-Frame-Options"] = "DENY"
    return response


#: flask app singleton?
class App:''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""
Standalone example of the same shape: register an after_request hook that
adds a Server-Timing header for local performance debugging -- purely
diagnostic, never a security boundary, unlike a framing-restriction
header.
"""
import time


def configure_timing_header(app):
    @app.after_request
    def add_server_timing(response):
        response.headers["Server-Timing"] = f"total;dur={time.process_time() * 1000:.1f}"
        return response
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
