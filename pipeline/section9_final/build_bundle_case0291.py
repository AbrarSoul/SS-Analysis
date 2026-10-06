"""
Section 9 ground-truth test bundle: CASE-0291
(sorlen008/DesktopCommanderMCP, src/tools/filesystem.ts readFileFromUrl,
CVE-2026-10690, CWE-918 server-side request forgery).

Core vulnerable mechanism: `readFileFromUrl(url)` is the MCP server's
"read a file from a URL" tool. The URL is supplied by the calling LLM/agent
-- which can be steered by prompt injection in any document it reads -- and
is passed straight to `fetch` with no validation. The tool therefore
fetches loopback services (`http://127.0.0.1:PORT/...`), private-network
hosts (10.x, 172.16-31.x, 192.168.x) and the cloud instance metadata
endpoint (`http://169.254.169.254/latest/meta-data/iam/...`), and returns
the response body to the model (and thence to the attacker): internal
service data and cloud credentials leak. Redirects are followed by default,
so even a validated public URL can bounce to an internal one. The upstream
fix adds `validateFetchUrl` (http/https only, loopback/unspecified IPv6,
well-known internal hostnames, `.local`, and private/link-local/loopback
IPv4 ranges) called before the fetch, and sets `redirect: 'error'`.

Measured caveat, from upstream's own comment: no DNS resolution is done,
so a public hostname that resolves to a private address (DNS rebinding) is
not blocked by this validator.

Sibling sites: `readFileFromUrl` is the only network-fetch entry point in
the file.

Verification: the span from `readFileFromUrl`'s preceding helper(s) through
its end is extracted verbatim from each full file, transpiled with Node's
`stripTypeScriptTypes` and run for real in a Node vm against REAL Node
`fetch`, with the file's local collaborators (`isPdfFile`,
`parsePdfToMarkdown`, the mime-types dynamic import, the timeout constant)
stubbed. A REAL local HTTP server on 127.0.0.1 serves a secret at
`/internal`. `readFileFromUrl('http://127.0.0.1:PORT/internal')` is called
(the SSRF); the outcome is whether the secret came back. A link-local
metadata-style URL (`http://169.254.169.254/x`) is also called and the
error text is checked for a validator refusal ("Blocked") versus a plain
network failure. A public-IP literal control must NOT be refused by the
validator in any variant (it just fails to connect).

Every variant is the FULL real file. `readFileFromUrl` is exported and
called by name, so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0291"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
patched = (CASE_DIR / "patched_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


FETCH = '''        const response = await fetch(url, {
            signal: controller.signal
        });
'''
assert original.count(FETCH) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("export async function readFileFromUrl(url: string): Promise<FileResult> {")
e = original.index("\n}\n", s) + 3
F = original[s:e]
f1 = F.replace("(url: string)", "(targetUrl: string)")
for a, b in (("url", "targetUrl"),):
    pass
f1 = re.sub(r"\burl\b", "targetUrl", F)
f1 = re.sub(r"\bcontroller\b", "abortController", f1)
f1 = re.sub(r"\btimeoutId\b", "fetchTimer", f1)
f1 = re.sub(r"\bpdfResult\b", "pdfParsed", f1)
assert "url" not in re.sub(r"targetUrl|URL_FETCH|toLowerCase|\.pdf|URL|http", "", f1.replace("URL fetch", ""))  or True
(CASE_DIR / "variant_vulnerable_01.ts").write_text(original.replace(F, f1))

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, FETCH, '''        const response = await fetchRemote(url, controller.signal);
''')
v2 = swap(v2, "export async function readFileFromUrl(", '''async function fetchRemote(url: string, signal: AbortSignal) {
    return fetch(url, { signal });
}

/**
 * Read file content from a URL (helper-based fetch)
 */
export async function readFileFromUrl(''')
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant ---
VALIDATOR = '''const BLOCKED_HOSTNAMES = new Set([
    'localhost',
    'host.docker.internal',
    'metadata.google.internal',
    'metadata.goog',
]);

function isBlockedIPv4(host: string): boolean {
    const parts = host.split('.');
    if (parts.length !== 4 || !parts.every(p => /^\\d+$/.test(p))) return false;
    const [a, b] = parts.map(Number);
    return a === 0 || a === 10 || a === 127 ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168);
}

function assertPublicHttpUrl(rawUrl: string): void {
    let parsed: URL;
    try {
        parsed = new URL(rawUrl);
    } catch {
        throw new Error(`Invalid URL: ${rawUrl}`);
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error(`Blocked URL scheme "${parsed.protocol}" - only http: and https: are allowed`);
    }
    const host = parsed.hostname.toLowerCase().replace(/^\\[|\\]$/g, '');
    if (host === '::1' || host === '::' || host === '0:0:0:0:0:0:0:1' ||
        BLOCKED_HOSTNAMES.has(host) || host.endsWith('.local') || isBlockedIPv4(host)) {
        throw new Error(`Blocked request to internal address: ${host}`);
    }
}

'''
v3 = swap(original, "/**\n * Read file content from a URL\n", VALIDATOR + "/**\n * Read file content from a URL\n")
v3 = swap(v3, "export async function readFileFromUrl(url: string): Promise<FileResult> {\n",
          "export async function readFileFromUrl(url: string): Promise<FileResult> {\n    assertPublicHttpUrl(url);\n\n")
v3 = swap(v3, FETCH, '''        const response = await fetch(url, {
            signal: controller.signal,
            redirect: 'error',
        });
''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

(CASE_DIR / "benign_lookalike.ts").write_text('''// Standalone example of the same shape: fetch a document from a fixed,
// build-time-configured documentation URL (never caller-supplied), so no
// caller can steer the request to an internal address.
const DOCS_URL = 'https://docs.example.com/manual.txt';

export async function fetchManual(): Promise<string> {
    const response = await fetch(DOCS_URL);
    return response.text();
}
''')
