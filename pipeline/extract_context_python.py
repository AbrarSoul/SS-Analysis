"""
Section 8 Step 5: extract fixed model context for the 10 Python pilot cases.

For each case, uses Python's ast module (stdlib, exact) to pull:
- the vulnerable function/method (from vulnerable_source.py)
- the patched function/method (from patched_source.py)
- all top-level imports
- the containing class's declaration line, when the target is a method
- CVE id, CWE id(s) + definitions (from metadata.json / cwe_definitions.json)
- the unified diff (already saved as patch.diff)

Target function identification is keyed by (function_name, class_name,
occurrence_index) -- hand-verified against each case during this session's
Section 9 work, re-confirmed here by requiring ast to actually find a
uniquely-matching node (KeyError/assertion if not, rather than silently
picking the wrong function).
"""
import ast
import json
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"
CWE_DEFS = json.loads((BENCH_DIR / "cwe_definitions.json").read_text())

# case_id -> (function_name, class_name_or_None, occurrence_index (0-based, for duplicate names))
TARGETS = {
    "CASE-0001": ("exec_code", "ToolExecutor", 0),
    "CASE-0002": ("execute", "Calculator", 0),
    "CASE-0003": ("getSpeakIoMessage", "LogMessage", 0),
    "CASE-0004": ("sync_tree", "HeteroDecisionTreeGuest", 0),
    "CASE-0005": ("get_user", "ParticipationAdmin", 0),
    "CASE-0006": ("read_users", None, 0),
    "CASE-0007": ("initialize", "PGVectorVectorIOAdapter", 0),
    "CASE-0008": ("install_app", None, 0),
    "CASE-0009": ("read_fixed_bytes", "PascalStyleByteStream", 0),
}


def find_function(tree: ast.Module, func_name: str, class_name: str | None, occurrence: int):
    """Returns (func_node, class_node_or_None) for the occurrence-th match."""
    matches = []
    # search at module level and inside every class
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            # find enclosing class, if any, by checking all ClassDef nodes for containment
            enclosing_class = None
            for cnode in ast.walk(tree):
                if isinstance(cnode, ast.ClassDef):
                    if any(child is node for child in ast.walk(cnode)):
                        # must be a DIRECT child (not itself matched via another nested class)
                        if node in cnode.body:
                            enclosing_class = cnode
            if class_name is not None:
                if enclosing_class is not None and enclosing_class.name == class_name:
                    matches.append((node, enclosing_class))
            else:
                if enclosing_class is None:
                    matches.append((node, None))
    assert len(matches) > occurrence, (
        f"expected at least {occurrence + 1} match(es) for {func_name} "
        f"(class={class_name}), found {len(matches)}"
    )
    return matches[occurrence]


def get_imports(tree: ast.Module) -> list[str]:
    lines = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            lines.append(ast.unparse(node))
    return lines


def extract_case(case_id: str, func_name: str, class_name: str | None, occurrence: int) -> dict:
    case_dir = BENCH_DIR / "cases" / case_id
    metadata = json.loads((case_dir / "metadata.json").read_text())

    vuln_src = (case_dir / "vulnerable_source.py").read_text()
    patched_src = (case_dir / "patched_source.py").read_text()

    vuln_tree = ast.parse(vuln_src)
    patched_tree = ast.parse(patched_src)

    vuln_func, vuln_class = find_function(vuln_tree, func_name, class_name, occurrence)
    patched_func, patched_class = find_function(patched_tree, func_name, class_name, occurrence)

    vuln_func_text = ast.get_source_segment(vuln_src, vuln_func)
    patched_func_text = ast.get_source_segment(patched_src, patched_func)
    assert vuln_func_text is not None and patched_func_text is not None

    vuln_class_decl = None
    if vuln_class is not None:
        # just the class declaration line (name + bases), not the full body
        bases = ", ".join(ast.unparse(b) for b in vuln_class.bases)
        vuln_class_decl = f"class {vuln_class.name}({bases}):" if bases else f"class {vuln_class.name}:"

    imports = get_imports(vuln_tree)

    diff_text = (case_dir / "patch.diff").read_text()

    cwe_ids = metadata["cwe_ids"]
    cwe_entries = [{"id": c, "definition": CWE_DEFS.get(c, "(definition not found)")} for c in cwe_ids]

    return {
        "case_id": case_id,
        "language": "python",
        "cve_id": metadata["cve_id"],
        "cwe": cwe_entries,
        "function_name": func_name,
        "class_name": vuln_class.name if vuln_class else None,
        "containing_class_declaration": vuln_class_decl,
        "imports": imports,
        "vulnerable_function": vuln_func_text,
        "patched_function": patched_func_text,
        "unified_diff": diff_text,
    }


def main():
    out_dir = BENCH_DIR / "model_context"
    out_dir.mkdir(exist_ok=True)
    for case_id, (func_name, class_name, occurrence) in TARGETS.items():
        result = extract_case(case_id, func_name, class_name, occurrence)
        out_path = out_dir / f"{case_id}.json"
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        print(
            f"{case_id}: {func_name} "
            f"(class={class_name}) -> vuln {len(result['vulnerable_function'])} chars, "
            f"patched {len(result['patched_function'])} chars, "
            f"{len(result['imports'])} imports"
        )


if __name__ == "__main__":
    main()
