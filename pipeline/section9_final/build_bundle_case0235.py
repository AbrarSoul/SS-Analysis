"""
Section 9 ground-truth test bundle: CASE-0235
(netristv/ws-scrcpy, src/server/services/HttpServer.ts createServer,
CVE-2021-3845, CWE-73 external control of file name / path traversal).

Core vulnerable mechanism: the static-file handler builds the file path with
`path.join(publicDir, (parsedUrl.pathname || '.').replace(/^(\\.)+/, '.'))`. The
`replace` only rewrites leading dots, and the pathname always starts with `/`,
so `/../secret.txt` is joined as `<public>/../secret.txt`, which `path.join`
normalises to `<parent>/secret.txt`: any file the server can read is served.
The upstream fix adds `if (pathname.indexOf(publicDir) !== 0) { 403 }`.

Measured caveat, kept in the manifest notes: `indexOf(publicDir) !== 0` is a STRING
prefix test. A sibling directory whose name begins with the public
directory's name (`.../public-secrets/` next to `.../public/`) still passes it,
so `/../public-secrets/key.txt` is served by the patched handler. The safe
variant resolves the path and requires it to equal the root or to start with
`root + path.sep`.

Sibling sites: the handler is the only place in the file that maps a URL to a file.

Verification: the file is converted to CommonJS (imports replaced by requires of
the real `http`, `url`, `path`, `fs`; `./Service` and `../Utils` stubbed), its
types are stripped with node:module.stripTypeScriptTypes, and
`HttpServer.getInstance().createServer(publicDir)` is started on a REAL http
server bound to an ephemeral port. Raw requests are sent (Node's http client does
not normalise the path) against a temp layout `public/`, `secret.txt` beside it and
a sibling `public-secrets/key.txt`.

Every variant is the FULL real file. `createServer` is called by `start()`, so its
name and signature are kept; the renamed variant renames locals inside the
request callback.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0235"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


JOIN = '''            const parsedUrl = url.parse(req.url);
            let pathname = path.join(publicDir, (parsedUrl.pathname || '.').replace(/^(\\.)+/, '.'));
'''
assert original.count(JOIN) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("        const server = http.createServer(")
e = original.index("        server.on('close'")
cb = original[s:e]
for a, b in (("parsedUrl", "requestUrl"), ("pathname", "filePath"), ("data", "content")):
    cb = re.sub(r"\b%s\b" % a, b, cb)
cb = cb.replace("requestUrl.filePath", "requestUrl.pathname")   # a property of url.parse's result keeps its name
assert "requestUrl.pathname" in cb
(CASE_DIR / "variant_vulnerable_01.ts").write_text(original[:s] + cb + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, JOIN, '''            let pathname = this.resolvePath(publicDir, req.url);
''')
v2 = swap(v2, "    private createServer(publicDir: string): http.Server {", '''    private resolvePath(publicDir: string, rawUrl: string): string {
        const parsedUrl = url.parse(rawUrl);
        return path.join(publicDir, (parsedUrl.pathname || '.').replace(/^(\\.)+/, '.'));
    }

    private createServer(publicDir: string): http.Server {''')
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, JOIN, '''            const parsedUrl = url.parse(req.url);
            const root = path.resolve(publicDir);
            let pathname = path.resolve(root, '.' + (parsedUrl.pathname || '/'));
            if (pathname !== root && !pathname.startsWith(root + path.sep)) {
                res.statusCode = 403;
                res.end();
                return;
            }
''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

BENIGN = '''// Standalone example of the same shape: map a URL path to a file for a fixed,
// server-defined list of documentation pages, never an arbitrary client path.
import path from 'path';

const PAGES: Record<string, string> = {
    '/': 'index.html',
    '/help': 'help.html',
};

export function pageFile(publicDir: string, pathname: string): string | undefined {
    const name = PAGES[pathname];
    return name ? path.join(publicDir, name) : undefined;
}
'''
(CASE_DIR / "benign_lookalike.ts").write_text(BENIGN)
