"""
Section 8 Step 5: extract fixed model context for the 10 Java pilot cases.

No stdlib Java parser is available, so this uses a careful brace-matching
scanner (aware of string/char literals and // and /* */ comments, so
braces inside them don't corrupt the count) anchored on each case's
hand-verified method/class signature text from this session's Section 9
work. CASE-0011 is a special case: the vulnerable unit is a static
initializer block, not a method.
"""
import json
import re
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
CWE_DEFS = json.loads((BENCH_DIR / "cwe_definitions.json").read_text())

# case_id -> (kind, method_or_block_anchor_regex, class_name)
# kind: "method" (anchor matches the signature line; extraction starts at
#   the next "{" at/after the anchor line and runs to its matching "}")
#   or "static_block" (anchor matches a line; same brace-matching applies)
TARGETS = {
    "CASE-0011": ("static_block", r"^\s*static \{\s*$", "SubTypeValidator"),
    "CASE-0012": ("method", r"getNextElementUpwards\(final DomNode startingNode\)", "DescendantElementsIterator"),
    "CASE-0013": ("method", r"public String postDataSource\(IDataSource dataSource\)", "DataSourceResource"),
    "CASE-0014": ("method", r"public static File createTempDir\(int port\)", "WarFileLauncher"),
    "CASE-0015": ("method", r"public void renderContent\(", "ServicesServlet"),
    "CASE-0016": ("method", r"getCuboidHitFrequency\(String cubeName, boolean isCuboidSource\)", "CubeService"),
    "CASE-0017": ("method", r"public String verifyAndExtract\(String signedStr\)", "CookieSigner"),
    "CASE-0018": ("method", r"public HttpResponse doFinishLogin\(StaplerRequest request\)", "GitLabSecurityRealm"),
    "CASE-0019": ("method", r"private static void processZipStream\(", "InputStreamHelper"),
    "CASE-0020": ("method", r"public SecurityFilterChain securityFilterChain\(", "SecurityConfiguration"),
}

CLASS_DECL_RE = re.compile(r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*"
                            r"(?:public |protected |private )?(?:static |final |abstract )*"
                            r"class\s+(\w+)")


def strip_literals_and_comments_for_brace_count(line: str, state: dict) -> str:
    """Returns a copy of line with string/char literal and comment content
    blanked out (but braces outside them preserved), tracking block-comment
    state across lines via `state['in_block_comment']`."""
    out = []
    i = 0
    n = len(line)
    in_string = False
    in_char = False
    while i < n:
        if state["in_block_comment"]:
            end = line.find("*/", i)
            if end == -1:
                i = n
            else:
                state["in_block_comment"] = False
                i = end + 2
            continue
        c = line[i]
        if in_string:
            out.append(" ")
            if c == "\\" and i + 1 < n:
                out.append(" ")
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if in_char:
            out.append(" ")
            if c == "\\" and i + 1 < n:
                out.append(" ")
                i += 2
                continue
            if c == "'":
                in_char = False
            i += 1
            continue
        if c == "/" and i + 1 < n and line[i + 1] == "/":
            break  # rest of line is a line comment
        if c == "/" and i + 1 < n and line[i + 1] == "*":
            state["in_block_comment"] = True
            i += 2
            continue
        if c == '"':
            in_string = True
            out.append(" ")
            i += 1
            continue
        if c == "'":
            in_char = True
            out.append(" ")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def extract_brace_block(lines: list[str], start_idx: int) -> str:
    """Starting search at lines[start_idx], finds the first '{' (scanning
    forward, ignoring literals/comments) and returns the full text from
    lines[start_idx] through the line containing the matching '}'."""
    state = {"in_block_comment": False}
    depth = 0
    started = False
    end_idx = None
    for idx in range(start_idx, len(lines)):
        clean = strip_literals_and_comments_for_brace_count(lines[idx], state)
        for ch in clean:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth == 0:
                    end_idx = idx
                    break
        if end_idx is not None:
            break
    assert end_idx is not None, f"never found matching close brace starting at line {start_idx + 1}"
    return "".join(lines[start_idx:end_idx + 1])


def find_anchor_line(lines: list[str], pattern: str) -> int:
    regex = re.compile(pattern)
    matches = [i for i, line in enumerate(lines) if regex.search(line)]
    assert len(matches) == 1, f"expected exactly 1 match for {pattern!r}, found {len(matches)}"
    return matches[0]


def find_class_declaration(lines: list[str], class_name: str) -> str:
    for line in lines:
        m = CLASS_DECL_RE.search(line)
        if m and m.group(1) == class_name:
            return line.strip()
    raise AssertionError(f"class declaration for {class_name!r} not found")


def get_imports(lines: list[str]) -> list[str]:
    return [line.strip() for line in lines if line.strip().startswith("import ")]


def extract_case(case_id: str, kind: str, anchor_pattern: str, class_name: str) -> dict:
    case_dir = BENCH_DIR / "cases" / case_id
    metadata = json.loads((case_dir / "metadata.json").read_text())

    vuln_lines = (case_dir / "vulnerable_source.java").read_text().splitlines(keepends=True)
    patched_lines = (case_dir / "patched_source.java").read_text().splitlines(keepends=True)

    vuln_anchor_idx = find_anchor_line(vuln_lines, anchor_pattern)
    vuln_text = extract_brace_block(vuln_lines, vuln_anchor_idx)

    # the patched file's anchor text is usually identical (only the body
    # changes) -- if the exact same anchor isn't found, this raises and
    # flags the case for manual handling rather than silently picking the
    # wrong method.
    patched_anchor_idx = find_anchor_line(patched_lines, anchor_pattern)
    patched_text = extract_brace_block(patched_lines, patched_anchor_idx)

    class_decl = find_class_declaration(vuln_lines, class_name)
    imports = get_imports(vuln_lines)

    diff_text = (case_dir / "patch.diff").read_text()

    cwe_ids = metadata["cwe_ids"]
    cwe_entries = [{"id": c, "definition": CWE_DEFS.get(c, "(definition not found)")} for c in cwe_ids]

    return {
        "case_id": case_id,
        "language": "java",
        "cve_id": metadata["cve_id"],
        "cwe": cwe_entries,
        "extraction_kind": kind,
        "class_name": class_name,
        "containing_class_declaration": class_decl,
        "imports": imports,
        "vulnerable_function": vuln_text,
        "patched_function": patched_text,
        "unified_diff": diff_text,
    }


def main():
    out_dir = BENCH_DIR / "model_context"
    out_dir.mkdir(exist_ok=True)
    for case_id, (kind, pattern, class_name) in TARGETS.items():
        result = extract_case(case_id, kind, pattern, class_name)
        out_path = out_dir / f"{case_id}.json"
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        print(
            f"{case_id}: {kind} in {class_name} -> vuln {len(result['vulnerable_function'])} chars, "
            f"patched {len(result['patched_function'])} chars, {len(result['imports'])} imports"
        )


if __name__ == "__main__":
    main()
