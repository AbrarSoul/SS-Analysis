"""
Section 8 Step 5: extract fixed model context for the 20 JavaScript/
TypeScript pilot cases.

Uses a character-offset-anchored brace matcher: each case specifies an
anchor SUBSTRING that ends exactly at the "{" which opens the target
function/method/block body. The anchor's position is found via a plain
substring search (unambiguous -- no line-based scanning that could be
confused by an earlier, fully-balanced brace pair on the same line, e.g.
a destructured parameter "({ input, ctx }) => {"), then brace depth is
counted forward from there, correctly skipping braces inside string,
char, and template literals (including "${...}" interpolation, which is
real nested code and is tracked with its own depth) and comments.

Every anchor was verified (via grep) to appear, unchanged, in both
vulnerable_source.* and patched_source.* before being hard-coded here.
CASE-0026 (a module-level statement, no enclosing function) and CASE-0023
(an anonymous jQuery callback whose surrounding statement is the
meaningful unit, not a "function" in the language sense) are handled as
explicit special cases rather than forced into the brace-matcher.
"""
import json
import re
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
CWE_DEFS = json.loads((BENCH_DIR / "cwe_definitions.json").read_text())


def extract_block_by_anchor(source: str, anchor: str) -> str:
    """anchor must be a substring ending in the target opening '{'."""
    assert anchor.endswith("{"), f"anchor must end with '{{': {anchor!r}"
    start = source.index(anchor)
    open_brace_pos = start + len(anchor) - 1
    assert source[open_brace_pos] == "{"

    i = open_brace_pos
    n = len(source)
    depth = 0
    # stack of modes: "code", "template", "template_expr"
    mode_stack = ["code"]
    in_string = None  # None, '"', or "'"
    in_line_comment = False
    in_block_comment = False

    while i < n:
        c = source[i]
        mode = mode_stack[-1]

        if in_line_comment:
            if c == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if c == "*" and i + 1 < n and source[i + 1] == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if c == "\\":
                i += 2
                continue
            if c == in_string:
                in_string = None
            i += 1
            continue

        if mode == "template":
            if c == "\\":
                i += 2
                continue
            if c == "`":
                mode_stack.pop()
                i += 1
                continue
            if c == "$" and i + 1 < n and source[i + 1] == "{":
                mode_stack.append("template_expr")
                i += 2
                continue
            i += 1
            continue

        # mode == "code" or "template_expr": real code, track comments/strings/braces
        if c == "/" and i + 1 < n and source[i + 1] == "/":
            in_line_comment = True
            i += 2
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "*":
            in_block_comment = True
            i += 2
            continue
        if c == '"' or c == "'":
            in_string = c
            i += 1
            continue
        if c == "`":
            mode_stack.append("template")
            i += 1
            continue
        if c == "{":
            if mode == "code":
                depth += 1
            i += 1
            continue
        if c == "}":
            if mode == "template_expr":
                mode_stack.pop()  # end of ${...}, back to "template"
            else:
                depth -= 1
                if depth == 0:
                    return source[start:i + 1]
            i += 1
            continue
        i += 1

    raise AssertionError(f"never found matching close brace for anchor {anchor!r}")


def get_imports(lines: list[str]) -> list[str]:
    out = []
    for line in lines:
        s = line.strip()
        if s.startswith("import ") or re.match(r"^(const|let|var)\s+.*=\s*require\(", s):
            out.append(s)
    return out


CLASS_DECL_RE = re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+(\w+)[^{]*\{", re.MULTILINE)


def find_enclosing_class_declaration(source: str, anchor_pos: int) -> str | None:
    """Finds the class declaration whose body span contains anchor_pos,
    preferring the innermost when classes are nested. Falls back to None
    if the anchor isn't inside any class (e.g. a top-level function)."""
    candidates = []
    for m in re.finditer(r"^[ \t]*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+\w+[^\n{]*\{", source, re.MULTILINE):
        class_start = m.start()
        if class_start >= anchor_pos:
            continue
        try:
            full_span = extract_block_by_anchor(source, source[class_start:m.end()])
        except AssertionError:
            continue
        class_end = class_start + len(full_span)
        if class_start <= anchor_pos < class_end:
            candidates.append((class_end - class_start, m.group().rstrip("{").strip()))
    if not candidates:
        return None
    # innermost = smallest enclosing span
    candidates.sort(key=lambda t: t[0])
    return candidates[0][1]


# case_id -> (ext, vuln_anchor, patched_anchor)  [anchors end in "{"]
# Special cases (CASE-0023, CASE-0026) are handled outside this table.
BRACE_ANCHOR_CASES = {
    "CASE-0021": ("js", "membersUtility.forgot = function(req, callback) {", "membersUtility.forgot = function(req, callback) {"),
    "CASE-0022": ("js", "async accept(connection) {", "async accept(connection) {"),
    "CASE-0024": ("js", "api.tools.parse_response = function(response) {", "api.tools.parse_response = function(response) {"),
    "CASE-0025": (
        "js",
        "function searchWithRipgrep({\n  searchPath,\n  pattern,\n  filePattern,\n  excludePatterns,\n  caseSensitive,\n  maxResults,\n}) {",
        "function searchWithRipgrep({\n  searchPath,\n  pattern,\n  filePattern,\n  excludePatterns,\n  caseSensitive,\n  maxResults,\n}) {",
    ),
    "CASE-0027": ("js", "function minify(req, res, next)\n{", "function minify(req, res, next)\n{"),
    "CASE-0028": ("js", "WebUtil.createCookie = function(name,value,days) {", "WebUtil.createCookie = function(name,value,days) {"),
    "CASE-0029": (".js", ".set('multiplier', function() {", ".set('multiplier', function() {"),
    "CASE-0030": ("js", "Decimal128.fromString = function(string) {", "Decimal128.fromString = function(string) {"),
    "CASE-0031": ("ts", ".query(async ({ input, ctx }) => {", ".query(async ({ input, ctx }) => {"),
    "CASE-0032": ("ts", "authHandler: (methodsLeft, partialSuccess, callback) => {", "authHandler: (methodsLeft, partialSuccess, callback) => {"),
    "CASE-0033": ("ts", "export default async function dectalk(text: string): Promise<Buffer> {", "export default async function dectalk(text: string): Promise<Buffer> {"),
    "CASE-0035": ("ts", "private async readUserFromDatastoreByCredentials(username: string, password: string): Promise<User> {", "private async readUserFromDatastoreByCredentials(username: string, password: string): Promise<User> {"),
    "CASE-0036": ("ts", 'case "mark_task_done": {', 'case "mark_task_done": {'),
    "CASE-0037": ("ts", "export function getPaths(name: string | undefined): Array<string | number> {", "export function getPaths(name: string | undefined): Array<string | number> {"),
    "CASE-0038": ("ts", "function render(content: string): string {", "function render(content: string): string {"),
    "CASE-0039": ("ts", "export function ping(\n  host: string,\n  callback: (err: Error, res?: PingResult, stdout?: string) => void\n): void {",
                  "export function ping(\n  host: string,\n  callback: (err: Error, res?: PingResult, stdout?: string) => void\n): void {"),
    "CASE-0040": ("ts", "export function handleExtractQueryParamsMiddleware(encryptionService?: StringEncrypter) {", "export function handleExtractQueryParamsMiddleware(encryptionService?: StringEncrypter) {"),
}
# CASE-0034 has no function/method target (a class + decorator config) --
# handled as its own special case below.


def common_fields(case_id: str, metadata: dict, case_dir: Path) -> dict:
    diff_text = (case_dir / "patch.diff").read_text()
    cwe_ids = metadata["cwe_ids"]
    cwe_entries = [{"id": c, "definition": CWE_DEFS.get(c, "(definition not found)")} for c in cwe_ids]
    return {
        "case_id": case_id,
        "language": metadata["language"],
        "cve_id": metadata["cve_id"],
        "cwe": cwe_entries,
        "unified_diff": diff_text,
    }


def main():
    out_dir = BENCH_DIR / "model_context"
    out_dir.mkdir(exist_ok=True)
    results = {}

    for case_id, (ext, vuln_anchor, patched_anchor) in BRACE_ANCHOR_CASES.items():
        ext = ext.lstrip(".")
        case_dir = BENCH_DIR / "cases" / case_id
        metadata = json.loads((case_dir / "metadata.json").read_text())
        vuln_src = (case_dir / f"vulnerable_source.{ext}").read_text()
        patched_src = (case_dir / f"patched_source.{ext}").read_text()

        vuln_text = extract_block_by_anchor(vuln_src, vuln_anchor)
        patched_text = extract_block_by_anchor(patched_src, patched_anchor)

        imports = get_imports(vuln_src.splitlines())
        class_decl = find_enclosing_class_declaration(vuln_src, vuln_src.index(vuln_anchor))

        result = common_fields(case_id, metadata, case_dir)
        result.update({
            "containing_class_declaration": class_decl,
            "imports": imports,
            "vulnerable_function": vuln_text,
            "patched_function": patched_text,
        })
        results[case_id] = result

    # --- CASE-0023: anonymous jQuery callback; the meaningful unit is the
    # whole `.change(function() {...});` statement, not a language-level
    # "function" -- anchor on the statement's own start/end text.
    case_id = "CASE-0023"
    case_dir = BENCH_DIR / "cases" / case_id
    metadata = json.loads((case_dir / "metadata.json").read_text())
    vuln_src = (case_dir / "vulnerable_source.js").read_text()
    patched_src = (case_dir / "patched_source.js").read_text()
    vuln_text = extract_block_by_anchor(
        vuln_src, "$(\"#enableConfirmData, \\\n\t\t\t#clearDataFrom, \\\n\t\t\t#dataAppCache, #dataCache, \\\n\t\t\t#dataCookies, #dataDownloads, \\\n\t\t\t#dataFileSystems, #dataFormData, \\\n\t\t\t#dataHistory, #dataIndexedDB, \\\n\t\t\t#dataLocalStorage, #dataPluginData, \\\n\t\t\t#dataPasswords, #dataWebSQL, \\\n\t\t\t#enableTimedForget, #timedForgetHour, \\\n\t\t\t#timedForgetMinute, #timedForgetTime, \\\n\t\t\t#setForgetTime\").change(function() {",
    )
    patched_text = extract_block_by_anchor(patched_src, "$('#setForgetTime').change(function() {")
    result = common_fields(case_id, metadata, case_dir)
    result.update({
        "containing_class_declaration": None,
        "imports": get_imports(vuln_src.splitlines()),
        "vulnerable_function": vuln_text,
        "patched_function": patched_text,
    })
    results[case_id] = result

    # --- CASE-0026: module-level statement, no enclosing function.
    case_id = "CASE-0026"
    case_dir = BENCH_DIR / "cases" / case_id
    metadata = json.loads((case_dir / "metadata.json").read_text())
    vuln_src = (case_dir / "vulnerable_source.js").read_text()
    patched_src = (case_dir / "patched_source.js").read_text()
    vuln_line = "const Namespaces = {};\n"
    patched_line = "const Namespaces = Object.create(null);\n"
    assert vuln_line in vuln_src and patched_line in patched_src
    result = common_fields(case_id, metadata, case_dir)
    result.update({
        "containing_class_declaration": None,
        "imports": get_imports(vuln_src.splitlines()),
        "vulnerable_function": vuln_line.rstrip("\n"),
        "patched_function": patched_line.rstrip("\n"),
        "extraction_notes": "Module-level statement, not inside any function; extracted verbatim.",
    })
    results[case_id] = result

    # --- CASE-0034: class-level decorator config, not a function.
    case_id = "CASE-0034"
    case_dir = BENCH_DIR / "cases" / case_id
    metadata = json.loads((case_dir / "metadata.json").read_text())
    vuln_src = (case_dir / "vulnerable_source.ts").read_text()
    patched_src = (case_dir / "patched_source.ts").read_text()
    vuln_text = extract_block_by_anchor(vuln_src, "@TableAccessControl({")
    patched_text = extract_block_by_anchor(patched_src, "@TableAccessControl({")
    # the decorator precedes (rather than is enclosed by) the class it
    # decorates, so find the nearest class declaration AFTER the anchor
    decorated_class_match = CLASS_DECL_RE.search(vuln_src, vuln_src.index("@TableAccessControl({"))
    result = common_fields(case_id, metadata, case_dir)
    result.update({
        "containing_class_declaration": decorated_class_match.group().rstrip("{").strip() if decorated_class_match else None,
        "imports": get_imports(vuln_src.splitlines()),
        "vulnerable_function": vuln_text,
        "patched_function": patched_text,
        "extraction_notes": "Class-level decorator configuration, not a function/method.",
    })
    results[case_id] = result

    for case_id in sorted(results):
        result = results[case_id]
        out_path = out_dir / f"{case_id}.json"
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        print(
            f"{case_id}: vuln {len(result['vulnerable_function'])} chars, "
            f"patched {len(result['patched_function'])} chars, "
            f"{len(result['imports'])} imports, class={result['containing_class_declaration']!r}"
        )


if __name__ == "__main__":
    main()
