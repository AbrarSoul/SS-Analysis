"""
Section 9 ground-truth test bundle: CASE-0268
(psi-4ward/psitransfer, lib/endpoints.js the `app.use(uploadAppPath +
"files", ...)` upload middleware, CVE-2024-31453, CWE-434 unrestricted
upload of a file with dangerous consequence -- re-upload onto an already
completed transfer).

Core vulnerable mechanism: psitransfer's TUS upload endpoint distinguishes
`GET` (blocked, 405) and `POST` (validates metadata and registers a brand
new partial upload) but treats every OTHER method -- crucially `PATCH`, the
TUS protocol's "append more bytes to this upload" verb -- as implicitly
fine: the handler falls straight through to `next()`, handing the request
to `tusboy` (the TUS server middleware) with no check on whether the file
id (`fid`) in the URL already belongs to a COMPLETED transfer. A file, once
uploaded, is immutable and its download link may already be shared/relied
upon by recipients; without this check, an attacker who knows or guesses a
`fid` (file ids are used directly in shareable download URLs) can send a
`PATCH` request for that same `fid` and have tusboy accept and append/
overwrite bytes onto the already-finished file, silently replacing content
someone else already trusts (or is about to download) with attacker-chosen
data -- e.g. swapping a legitimate document for malware while the
download link and displayed metadata (name, size showed at share time)
stay unchanged. The upstream fix adds an early check, for both `POST` and
`PATCH`: look up `store.info(fid)`; if that upload exists and
`!info.isPartial` (i.e. it already completed), reject with `400 Upload
already completed`. A `store.info()` miss (brand new `fid`, the normal
POST-then-PATCH-sequence case) throws and is caught, letting the request
proceed as before.

Sibling sites: this `app.use` middleware is the only place in the file that
handles TUS upload requests; there is one call site to fix.

Verification: each full file's middleware function -- `function(req, res,
next) { ... }`, the first argument of the `app.use(uploadAppPath + "files",
...)` call -- is extracted verbatim and run as real JS with real `assert`
(Node builtin) and the real `http-errors` package (`httpErrors.NotFound`),
plus minimal stand-ins for `config`, `tusMeta`, `uuid`, and `db.add`
(recorder), and a controllable `store.info(fid)` stand-in that resolves to
`{isPartial: false}` (an already-completed upload) or rejects with
`httpErrors.NotFound()` (a brand-new upload) depending on the test case.
Invoked once with `method: 'PATCH'` against a completed upload's `fid`
(the attack: re-upload onto a finished transfer) and once with `method:
'PATCH'` against a still-partial upload's `fid` (the legitimate resume
case, used as a control).

Every variant is the FULL real file. The upload middleware is wired into
Express via `app.use(...)` at module load and is never called by name
elsewhere, so its anonymous-function form is kept; the renamed variant
renames its own locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0268"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


HANDLER_HEAD = """app.use(`${ config.uploadAppPath }files`,
  function(req, res, next) {
    // Upload password protection
    if (config.uploadPass) {
"""
assert original.count(HANDLER_HEAD) == 1

HANDLER_TAIL = """    next();
  },

  // let tusboy handle the upload
  tusboy(store, {"""
assert original.count(HANDLER_TAIL) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, HANDLER_HEAD, """app.use(`${ config.uploadAppPath }files`,
  function(request, response, cb) {
    // Upload password protection
    if (config.uploadPass) {
""")
v1 = v1.replace(
    """      const bfTimeout = 500;
      if (!req.get('x-passwd')) {
        setTimeout(() => res.status(401).send('Unauthorized'), bfTimeout);
        return;
      }
      if (req.get('x-passwd') !== config.uploadPass) {
        setTimeout(() => res.status(403).send('Forbidden'), bfTimeout);
        return;
      }
    }

    if (req.method === 'GET') return res.status(405).end();

    if (req.method === 'POST') {
      // validate meta-data
      // !! tusMeta.encode supports only strings !!
      const meta = tusMeta.decode(req.get('Upload-Metadata'));""",
    """      const bfTimeout = 500;
      if (!request.get('x-passwd')) {
        setTimeout(() => response.status(401).send('Unauthorized'), bfTimeout);
        return;
      }
      if (request.get('x-passwd') !== config.uploadPass) {
        setTimeout(() => response.status(403).send('Forbidden'), bfTimeout);
        return;
      }
    }

    if (request.method === 'GET') return response.status(405).end();

    if (request.method === 'POST') {
      // validate meta-data
      // !! tusMeta.encode supports only strings !!
      const meta = tusMeta.decode(request.get('Upload-Metadata'));""",
)
v1 = v1.replace(
    """        if (config.maxFileSize && config.maxFileSize < +uploadLength) {
          return res
            .status(413)
            .json({ message: `File exceeds maximum upload size ${ config.maxFileSize }.` });
        } else if (config.maxBucketSize && db.bucketSize(meta.sid) + +uploadLength > config.maxBucketSize) {
          return res
            .status(413)
            .json({ message: `Bucket exceeds maximum upload size ${ config.maxBucketSize }.` });
        }

        // store changed metadata for tusboy
        req.headers['upload-metadata'] = tusMeta.encode(meta);
        // for tusboy getKey()
        req.FID = meta.sid + '++' + meta.key;""",
    """        if (config.maxFileSize && config.maxFileSize < +uploadLength) {
          return response
            .status(413)
            .json({ message: `File exceeds maximum upload size ${ config.maxFileSize }.` });
        } else if (config.maxBucketSize && db.bucketSize(meta.sid) + +uploadLength > config.maxBucketSize) {
          return response
            .status(413)
            .json({ message: `Bucket exceeds maximum upload size ${ config.maxBucketSize }.` });
        }

        // store changed metadata for tusboy
        request.headers['upload-metadata'] = tusMeta.encode(meta);
        // for tusboy getKey()
        request.FID = meta.sid + '++' + meta.key;""",
)
v1 = swap(v1, "const uploadLength = req.get('Upload-Length');",
          "const uploadLength = request.get('Upload-Length');")
v1 = swap(v1, """      catch (e) {
        console.error(e);
        return res.status(400).end(e.message);
      }
    }

    next();
  },""", """      catch (e) {
        console.error(e);
        return response.status(400).end(e.message);
      }
    }

    cb();
  },""")
assert "function(request, response, cb)" in v1 and "cb();" in v1
assert "req.get" not in v1[v1.index("function(request, response, cb)"):v1.index("cb();")]
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
OLD_METHOD_CHECKS = """    if (req.method === 'GET') return res.status(405).end();

    if (req.method === 'POST') {"""
assert original.count(OLD_METHOD_CHECKS) == 1
v2 = swap(original, OLD_METHOD_CHECKS, """    if (isRejectedMethod(req)) return res.status(405).end();

    if (req.method === 'POST') {""")
v2 = swap(v2, "app.use(`${ config.uploadAppPath }files`,\n  function(req, res, next) {",
          "function isRejectedMethod (req) {\n  return req.method === 'GET';\n}\n\napp.use(`${ config.uploadAppPath }files`,\n  function(req, res, next) {")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (reject POST/PATCH to a fid whose upload is
# already complete) but written as an async IIFE returning a boolean,
# instead of upstream's inline try/catch directly in the handler body.
NEW_METHOD_CHECKS = """    if (req.method === 'GET') return res.status(405).end();

    if (['POST', 'PATCH'].includes(req.method)) {
      const fid = req.url.substring(1);
      const alreadyCompleted = await (async () => {
        try {
          const info = await store.info(fid);
          return !info.isPartial;
        } catch (e) {
          if (e instanceof httpErrors.NotFound) return false;
          console.error(e);
          return true;
        }
      })();
      if (alreadyCompleted) {
        return res.status(400).end('Upload already completed');
      }
    }

    if (req.method === 'POST') {"""
v3 = swap(original, OLD_METHOD_CHECKS, NEW_METHOD_CHECKS)
v3 = swap(v3, "  function(req, res, next) {\n    // Upload password protection",
          "  async function(req, res, next) {\n    // Upload password protection")
v3 = swap(v3, 'const { createGzip } = require("zlib");\n',
          'const { createGzip } = require("zlib");\nconst httpErrors = require("http-errors");\n')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = """// Standalone example of the same shape: skip an EXPENSIVE thumbnail
// regeneration step if one was already generated for this exact image
// hash (a cache-hit optimization), never a security boundary -- serving
// the cached thumbnail again is harmless either way.
async function regenerateThumbnailIfNeeded (imageHash, thumbnailStore) {
  const cached = await thumbnailStore.has(imageHash).catch(() => false);
  if (cached) return thumbnailStore.get(imageHash);
  return thumbnailStore.generate(imageHash);
}

module.exports = { regenerateThumbnailIfNeeded };
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
