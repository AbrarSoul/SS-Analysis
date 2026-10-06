"""
Section 9 ground-truth test bundle: CASE-0240
(ome/omero-web, omeroweb/webgateway/views.py jsonp, CVE-2024-35180,
CWE-830 inclusion of web functionality / reflected script injection through a
JSONP callback).

Core vulnerable mechanism: the `jsonp` decorator, and three other views in the same
file, answer a request that has a `callback` query parameter with
`"%s(%s)" % (callback, json_data)` returned as `application/javascript`. The
callback name is copied into the script unchecked, so
`?callback=alert(document.domain)//` produces JavaScript that runs the attacker's
expression when the URL is loaded through a `<script src=...>` on a page the
attacker controls, with the victim's OMERO session cookie attached to the request
(cross-site script inclusion / reflected script injection). The upstream fix adds
`VALID_JS_VARIABLE = re.compile(r"^[a-zA-Z_$][0-9a-zA-Z_$]*$")` and makes `jsonp`
return `HttpResponseBadRequest("Invalid callback")` for other values.

Sibling sites: the same unchecked `"%s(%s)" % (callback, ...)` appears in three
further views: the `dryrun` branch of the download view (`c = request.GET.get("callback")`),
the view that saves an image's rendering settings and returns "true"/"false"
(`request.GET["callback"]`), and the view that lists images whose channels
match (`r["callback"]`). The upstream patch validates only the `jsonp` decorator, so
those three still reflect the raw callback in the patched file; the vulnerable
variants leave all four unchanged and the safe variant validates all four.

Verification: the `jsonp` decorator (with any helper/constant) and the three
sibling snippets are extracted verbatim from each full file (the rest of those
large views, which need omero and a database, is omitted) and run with stand-ins for
`HttpJavascriptResponse`, `HttpResponse`, `HttpResponseBadRequest` and
`JsonResponse`. Requests carry `callback=cb123` (benign) or
`callback=alert(document.domain)//` (payload).

Every variant is the FULL real file. `jsonp` is a decorator applied by name across the
file, so its name and signature are kept; the renamed variant renames locals of
`wrap`.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0240"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


JSONP = '''            c = request.GET.get("callback", None)
            if c is not None and not kwargs.get("_internal", False):
                rv = json.dumps(rv)
                rv = "%s(%s)" % (c, rv)
                # mimetype for JSONP is application/javascript
                return HttpJavascriptResponse(rv)
'''
DRY = '''        c = request.GET.get("callback", None)
        if c is not None and not kwargs.get("_internal", False):
            rv = "%s(%s)" % (c, rv)
        return HttpJavascriptResponse(rv)
'''
SAVE = '''    if request.GET.get("callback", None):
        json_data = "%s(%s)" % (request.GET["callback"], json_data)
    return HttpJavascriptResponse(json_data)
'''
MATCH = '''    if r.get("callback", None):
        json_data = "%s(%s)" % (r["callback"], json_data)
    return HttpJavascriptResponse(json_data)
'''
for block in (JSONP, DRY, SAVE, MATCH):
    assert original.count(block) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, JSONP, '''            callback_name = request.GET.get("callback", None)
            if callback_name is not None and not kwargs.get("_internal", False):
                rv = json.dumps(rv)
                rv = "%s(%s)" % (callback_name, rv)
                # mimetype for JSONP is application/javascript
                return HttpJavascriptResponse(rv)
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, JSONP, '''            c = request.GET.get("callback", None)
            if c is not None and not kwargs.get("_internal", False):
                # mimetype for JSONP is application/javascript
                return HttpJavascriptResponse(_as_jsonp(c, json.dumps(rv)))
''')
v2 = swap(v2, "def jsonp(f):", '''def _as_jsonp(callback, payload):
    return "%s(%s)" % (callback, payload)


def jsonp(f):''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# One helper decides whether a callback name is a plain identifier; every site that
# reflects a callback asks it first.
v3 = swap(original, "class UserProxy(object):", '''_JS_IDENTIFIER = re.compile(r"[a-zA-Z_$][0-9a-zA-Z_$]*\\Z")


def _is_valid_callback(name):
    return _JS_IDENTIFIER.match(name) is not None


class UserProxy(object):''')
v3 = swap(v3, JSONP, '''            c = request.GET.get("callback", None)
            if c is not None and not kwargs.get("_internal", False):
                if not _is_valid_callback(c):
                    return HttpResponseBadRequest("Invalid callback")
                rv = json.dumps(rv)
                rv = "%s(%s)" % (c, rv)
                # mimetype for JSONP is application/javascript
                return HttpJavascriptResponse(rv)
''')
v3 = swap(v3, DRY, '''        c = request.GET.get("callback", None)
        if c is not None and not kwargs.get("_internal", False):
            if not _is_valid_callback(c):
                return HttpResponseBadRequest("Invalid callback")
            rv = "%s(%s)" % (c, rv)
        return HttpJavascriptResponse(rv)
''')
v3 = swap(v3, SAVE, '''    if request.GET.get("callback", None):
        if not _is_valid_callback(request.GET["callback"]):
            return HttpResponseBadRequest("Invalid callback")
        json_data = "%s(%s)" % (request.GET["callback"], json_data)
    return HttpJavascriptResponse(json_data)
''')
v3 = swap(v3, MATCH, '''    if r.get("callback", None):
        if not _is_valid_callback(r["callback"]):
            return HttpResponseBadRequest("Invalid callback")
        json_data = "%s(%s)" % (r["callback"], json_data)
    return HttpJavascriptResponse(json_data)
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: wrap a JSON payload in a callback
name chosen by the SERVER from a fixed list, never by the request."""
import json

ALLOWED_CALLBACKS = {"onImages", "onRois"}


def as_script(kind, payload):
    name = "onImages" if kind == "images" else "onRois"
    assert name in ALLOWED_CALLBACKS
    return "%s(%s)" % (name, json.dumps(payload))
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
