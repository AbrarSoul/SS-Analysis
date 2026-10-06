"""
Section 9 ground-truth test bundle: CASE-0261
(plone/volto, packages/volto/src/middleware/api.js apiMiddlewareFactory,
CVE-2025-61668, CWE-476/CWE-754 improper handling of unexpected/null
condition via unchecked null-pointer dereference).

Core vulnerable mechanism: inside the Redux api middleware's request-rejection
handler, when an in-flight API call for an action listed in
`settings.actions_raising_api_errors` fails with `error.response.statusCode
=== 401` (Unauthorized), the handler reads
`message: error.response.body.message`. Many 401 responses (an expired
session, a reverse proxy/auth gateway rejecting the request before it reaches
Plone, a HEAD request, or any backend that replies 401 with an empty or
non-JSON body) never populate `error.response.body`, leaving it `undefined`.
Dereferencing `.message` off `undefined` throws a `TypeError` synchronously
inside the `.then()` rejection callback, which is unhandled (this callback IS
the rejection handler, so there is no further `.catch` upstream to absorb it)
and crashes the middleware chain client-side, and on the server can bring
down SSR rendering for that request. The upstream fix changes only that one
line to `message: error.response?.body?.message,`, using optional chaining so
a missing `body` degrades to `message: undefined` instead of throwing.

Sibling sites: the other three branches inside the same
`actions_raising_api_errors` switch (504 gateway timeout, 301/408 redirect)
and the two branches above it (ECONNREFUSED, crossDomain) all read `error.code`
or `error.crossDomain` directly off `error`/`error.response`, never a second
level deep into a field the server response controls (`body`), so none of
them can throw on a missing/empty body the way the 401 branch does; this is
the only unchecked two-level-deep dereference of server-controlled data in
the file.

Verification: each full file's rejection handler -- the `.then()` call's
second callback, `(error) => { ... }` -- is extracted verbatim (locations
differ slightly per variant: the renamed variant renames the parameter to
`err` throughout, correcting only the object-shorthand `error` keys back to
`error: <param>` so the dispatched action's shape is unchanged; the
structurally-changed variant keeps the same handler body but has the 401
branch call an extracted `buildUnauthorizedAction` helper) and run as real,
unmodified JS in a Node harness with stand-ins only for the outer closure
variables the handler reads (`next` as a recorder, `rest`, `type`, `action`,
`settings.actions_raising_api_errors`, `SET_APIERROR`, `isHydrating`,
`hasExistingError`) -- no third-party packages needed, since the handler
itself calls nothing but `next()`. It is invoked twice: once with
`error = { response: { statusCode: 401 } }` (no `body`, the crash case) and
once with `error = { response: { statusCode: 401, body: { message: 'nope' }
} }` (the normal case, to confirm the fix does not change well-formed
behavior). Vulnerable variants throw a TypeError on the first call; the safe
variant does not, and reports `message: undefined` from `next()`.

Every variant is the FULL real file. `apiMiddlewareFactory` is imported by
name (`import apiMiddlewareFactory from '@plone/volto/middleware/api'`)
elsewhere in the app and wired into the Redux store, so its export shape and
the dispatched `SET_APIERROR` action's field names (`error`, `statusCode`,
`message`, `connectionRefused`, `type`) are kept; the renamed variant renames
only the rejection handler's own parameter and local usages.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0261"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
# Rename only the rejection handler's `error` parameter to `err`, everywhere
# it is a bare reference; restore `error:` as the explicit key wherever it
# was previously an object-shorthand property (so the dispatched action's
# field name, read by reducers elsewhere, is unchanged).
start_marker = "(error) => {"
assert original.count(start_marker) == 1
start_idx = original.index(start_marker)
end_marker = "return next({ ...rest, error, type: `${type}_FAIL` });"
assert original.count(end_marker) == 1
end_idx = original.index(end_marker) + len(end_marker)
handler_text = original[start_idx:end_idx]

renamed_handler = re.sub(r"\berror\b", "err", handler_text)
renamed_handler = re.sub(r"\berr\b(?=,)", "error: err", renamed_handler)
assert "(err) => {" in renamed_handler
assert "err.response.body.message" in renamed_handler
assert "error: err," in renamed_handler  # shorthand keys restored

v1 = original[:start_idx] + renamed_handler + original[end_idx:]
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
# Extract the 401 branch's action-building into a standalone helper function;
# it still dereferences `error.response.body.message` directly, so it still
# throws on a bodyless 401.
OLD_401_BRANCH = """            // Unauthorized
            else if (error?.response?.statusCode === 401) {
              next({
                ...rest,
                error,
                statusCode: error.response,
                message: error.response.body.message,
                connectionRefused: false,
                type: SET_APIERROR,
              });
            }
"""
assert original.count(OLD_401_BRANCH) == 1
NEW_401_BRANCH = """            // Unauthorized
            else if (error?.response?.statusCode === 401) {
              next(buildUnauthorizedAction(rest, error));
            }
"""
v2 = swap(original, OLD_401_BRANCH, NEW_401_BRANCH)
HELPER = """function buildUnauthorizedAction(rest, error) {
  return {
    ...rest,
    error,
    statusCode: error.response,
    message: error.response.body.message,
    connectionRefused: false,
    type: SET_APIERROR,
  };
}

"""
v2 = swap(v2, "const apiMiddlewareFactory =\n", HELPER + "const apiMiddlewareFactory =\n")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (no crash on a missing body) but written as an
# explicit guarded expression instead of upstream's optional-chaining edit,
# so the safe variant is not a byte-for-byte copy of the real patch.
OLD_MESSAGE_LINE = "                message: error.response.body.message,\n"
assert original.count(OLD_MESSAGE_LINE) == 1
NEW_MESSAGE_LINE = (
    "                message:\n"
    "                  error.response && error.response.body\n"
    "                    ? error.response.body.message\n"
    "                    : undefined,\n"
)
v3 = swap(original, OLD_MESSAGE_LINE, NEW_MESSAGE_LINE)
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = """/**
 * Standalone example of the same shape: read an optional, nested field off a
 * value this module itself constructs (a local settings object with a fixed,
 * known shape), never data an external server response controls, so a
 * missing intermediate field is a static, unit-testable non-issue rather
 * than something to guard defensively.
 */
const DEFAULT_THEME = { colors: { accent: '#0b5fff' } };

export function getAccentColor(theme) {
  const merged = { ...DEFAULT_THEME, ...theme };
  return merged.colors.accent;
}
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
