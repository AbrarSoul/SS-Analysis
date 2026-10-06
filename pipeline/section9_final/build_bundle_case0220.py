"""
Section 9 ground-truth test bundle: CASE-0220
(mhuertos/phpLDAPadmin, htdocs/js/ajax_functions.js makeHttpRequest,
CVE-2016-15039, CWE-444 inconsistent interpretation of HTTP requests /
request smuggling).

Core vulnerable mechanism: `makeHttpRequest` builds every AJAX call itself and,
besides Content-type, sets `Content-length` to `parameters.length` and
`Connection: close` by hand with setRequestHeader. Those are headers the
browser owns; scripts that force them make the framing of the request depend on
the script's own arithmetic instead of on the bytes actually sent. Two
concrete mismatches follow: (a) for `GET` the code appends the parameters to
the URL and then sends `null`, yet the request still carries a
`Content-length` of `parameters.length` and no body, and (b) `parameters.length`
counts UTF-16 characters, not the UTF-8 bytes of a body that contains
non-ASCII text. A proxy or server that honours the header (older browsers
and some XHR implementations pass it through) and the peer that follows the
real body then disagree on where the request ends. The upstream fix deletes
the two setRequestHeader calls.

Measured caveat, kept in the manifest notes: current browsers refuse to set
these two headers (they are on the forbidden-header list), so the exposure is
to older/embedded XHR implementations; the harness uses a stand-in XHR that
records what the script asked for rather than a real network stack.

Sibling sites: makeHttpRequest is the only place in the file that calls
setRequestHeader, and it is the only request builder.

Verification: each full variant is loaded, as the real file, into a Node `vm`
context with a stand-in `window`/`XMLHttpRequest` that records the headers set
and the body sent; `makeHttpRequest` is then called for a GET with ASCII
parameters and for a POST with a body containing a non-ASCII character.

Every variant is the FULL real file. makeHttpRequest is called by name from
other scripts and from inline handlers, so its name and parameter order are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0220"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


HDRS = '''	http_request.setRequestHeader('Content-type','application/x-www-form-urlencoded');
	http_request.setRequestHeader('Content-length',parameters.length);
	http_request.setRequestHeader('Connection','close');
'''
assert original.count(HDRS) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("function makeHttpRequest(")
e = original.index("\nfunction getParameters(")
fn = original[s:e]
head_end = fn.index("{") + 1
new_head = "function makeHttpRequest(url,parameters,meth,successCallbackFunctionName,errorCallbackFunctionName,div) {"
assert fn.startswith(new_head)
body = fn[len(new_head):]
import re
for a, b in (("url", "target"), ("parameters", "formData"), ("meth", "verb")):
    body = re.sub(r"\b%s\b" % a, b, body)  # whole identifiers only ('urlencoded' must stay)
assert "verb ==" in body and "formData.length" in body and "x-www-form-urlencoded" in body and "open(verb,target" in body
fn1 = "function makeHttpRequest(target,formData,verb,successCallbackFunctionName,errorCallbackFunctionName,div) {" + body
(CASE_DIR / "variant_vulnerable_01.js").write_text(original[:s] + fn1 + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, HDRS, '''	setFormHeaders(http_request,parameters);
''')
v2 = swap(v2, "function makeHttpRequest(", '''function setFormHeaders(request,parameters) {
	request.setRequestHeader('Content-type','application/x-www-form-urlencoded');
	request.setRequestHeader('Content-length',parameters.length);
	request.setRequestHeader('Connection','close');
}

function makeHttpRequest(''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Only declares a content type when a body is actually sent; leaves framing
# headers (Content-length, Connection) entirely to the browser.
v3 = swap(original, HDRS, '''	if (meth != 'GET') {
		http_request.setRequestHeader('Content-type','application/x-www-form-urlencoded');
	}
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: a small XHR helper that sets only the
// content type of the body it sends and lets the browser handle framing.
function postJson(url, payload, onDone) {
	var request = new XMLHttpRequest();
	request.open('POST', url, true);
	request.setRequestHeader('Content-type', 'application/json');
	request.onreadystatechange = function () {
		if (request.readyState === 4) onDone(request.status, request.responseText);
	};
	request.send(JSON.stringify(payload));
}
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
