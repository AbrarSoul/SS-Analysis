"""
Section 9 ground-truth test bundle: CASE-0254
(parisneo/lollms, backend/routers/files.py _download_image_to_temp,
CVE-2026-0560, CWE-918 server-side request forgery).

Core vulnerable mechanism: exporting a message to DOCX (or PPTX) walks the HTML for
`<img src=...>` and calls `_download_image_to_temp(src)`, which does
`requests.get(src, timeout=10)` on whatever URL the (user-authored) content contains.
An attacker who can put `<img src="http://169.254.169.254/latest/meta-data/...">`
or `http://127.0.0.1:9600/...` into a message makes the server request internal
services and embeds the response in the exported document. The upstream fix adds
`_validate_url`: http/https only, and the host, when an IP literal or a resolved name,
must not be private, loopback or link-local.

Measured caveats, kept in the manifest notes: (1) `_validate_url` resolves the host
and then `requests.get` resolves it AGAIN, so a name that answers with a public address for the
check and 127.0.0.1 for the request (DNS rebinding) passes validation and reaches the
internal service; (2) the `is_multicast` / `is_reserved` check on an IP literal raises a
ValueError inside the `try` whose `except ValueError` is meant for "not an IP address",
so it is swallowed and the code falls through to the name-resolution branch, which only
tests private/loopback/link-local: `http://224.0.0.1/` (multicast) is accepted (a reserved
literal such as 240.0.0.1 is blocked anyway because Python counts it as private); (3)
`requests.get` still follows redirects, which the validation never sees (not measured
here, it needs a public redirector). The safe variant resolves once, requires every
address to be globally routable and not multicast/reserved (`is_global` alone accepts 224.0.0.1), connects to that pinned address and does not follow
redirects.

Sibling sites: every caller (`html_to_docx_bytes`, `md_to_pptx_bytes`) goes through
`_download_image_to_temp`, so fixing it fixes them. The DOCX caller's `except Exception`
placeholder also changes in the upstream patch (message only).

Verification: `_validate_url` (fixed forms) and `_download_image_to_temp` are extracted
from each full file and run with the REAL `requests`, `ipaddress`, `socket` and
`http.client` against a local HTTP server on 127.0.0.1 that records requests. Cases: the
URL of that server (`http://127.0.0.1:<port>/x.png`), a name `public.example` whose
`socket.getaddrinfo` answer is a public address the first time and 127.0.0.1 afterwards
(rebinding), and `http://224.0.0.1/x.png` (multicast); for the pinned fetch `socket.create_connection`
is stubbed to record the address it would connect to.

Every variant is the FULL real file. `_download_image_to_temp` is called by name from the
DOCX and PPTX builders, so its name and signature are kept; the renamed variant renames
locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0254"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


FETCH = '''    r = requests.get(src, timeout=10)
    r.raise_for_status()
    ext = os.path.splitext(src)[1] or ".png"
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    tf.write(r.content)
    tf.flush(); tf.close()
    return tf.name
'''
assert original.count(FETCH) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, FETCH, '''    resp = requests.get(src, timeout=10)
    resp.raise_for_status()
    file_ext = os.path.splitext(src)[1] or ".png"
    out = tempfile.NamedTemporaryFile(delete=False, suffix=file_ext)
    out.write(resp.content)
    out.flush(); out.close()
    return out.name
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, FETCH, '''    content = _fetch_bytes(src)
    ext = os.path.splitext(src)[1] or ".png"
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    tf.write(content)
    tf.flush(); tf.close()
    return tf.name
''')
v2 = swap(v2, "def _download_image_to_temp(src: str) -> str:", '''def _fetch_bytes(src: str) -> bytes:
    r = requests.get(src, timeout=10)
    r.raise_for_status()
    return r.content

def _download_image_to_temp(src: str) -> str:''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "import requests\n", "import requests\nimport socket\nimport ssl\nimport ipaddress\nimport http.client\nfrom urllib.parse import urlparse\n")
v3 = swap(v3, FETCH, '''    content = _fetch_public_bytes(src)
    ext = os.path.splitext(src)[1] or ".png"
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    tf.write(content)
    tf.flush(); tf.close()
    return tf.name
''')
v3 = swap(v3, "def _download_image_to_temp(src: str) -> str:", '''def _fetch_public_bytes(url: str) -> bytes:
    """Fetch an http(s) URL from a globally routable address: resolve once, check every
    address, connect to that pinned address, and never follow redirects."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL validation failed: unsupported scheme or host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    if not infos:
        raise ValueError("URL validation failed: host does not resolve")
    addresses = [ipaddress.ip_address(info[4][0]) for info in infos]
    if not all(a.is_global and not (a.is_multicast or a.is_reserved or a.is_unspecified or a.is_loopback
                                    or a.is_link_local) for a in addresses):
        raise ValueError("URL validation failed: host is not a public address")
    pinned = str(addresses[0])
    sock = socket.create_connection((pinned, port), timeout=10)
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=10,
                                           context=ssl.create_default_context())
        conn.sock = conn._context.wrap_socket(sock, server_hostname=parsed.hostname)
    else:
        conn = http.client.HTTPConnection(parsed.hostname, port, timeout=10)
        conn.sock = sock
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    conn.request("GET", path, headers={"Host": parsed.netloc})
    response = conn.getresponse()
    if response.status != 200:
        raise ValueError("unexpected HTTP status %s" % response.status)
    data = response.read()
    conn.close()
    return data

def _download_image_to_temp(src: str) -> str:''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: download an image from a fixed,
server-configured CDN host only (the host comes from settings, never from user content)."""
import requests

CDN_BASE = "https://cdn.example.com/static/"


def download_static(name: str) -> bytes:
    r = requests.get(CDN_BASE + name.lstrip("/"), timeout=10)
    r.raise_for_status()
    return r.content
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
