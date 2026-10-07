"""
Section 8 Step 6: classify difficulty for all 40 pilot cases.

Records, per the design doc's Step 6 list:
- Language, CWE (from metadata.json, already verified during Step 4)
- Changed lines, changed files (computed directly from patch.diff)
- Function size (character and line count of the extracted vulnerable
  function/method from Step 5's model_context)
- Pattern-or-taint requirement: whether a Semgrep rule could plausibly
  flag the vulnerable instance via a local syntactic/AST pattern (a
  specific dangerous call, a missing specific check, an unsafe literal)
  versus needing to track a value's flow from an untrusted source to a
  sink across multiple statements/variables (taint mode)
- Structural-or-context-heavy category: whether the vulnerable pattern is
  self-contained within a few lines versus needing broader context
  (sibling methods/endpoints in the same file, cross-cutting knowledge of
  what "correct" looks like elsewhere, or framework-specific semantics)
  to distinguish the vulnerable instance from a superficially similar but
  safe one -- directly informed by this session's benign_lookalike.*
  construction for each case, which is exactly the test of this
  distinction
- Supported/partially-supported status (semgrep_representability from
  metadata.json, already assessed during Step 4)

pattern_or_taint and structural_or_context_heavy are judgment calls made
from this session's direct, hands-on construction of every case's Section
9 ground-truth bundle (each case's vulnerable mechanism, and specifically
what a benign look-alike needs to differ on to stay safe, was worked out
in detail while building that bundle earlier today).
"""
import json
import re
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"

# case_id -> (pattern_or_taint, structural_or_context_heavy, rationale)
JUDGMENT = {
    "CASE-0001": ("taint", "context_heavy",
                  "Predictable uuid7 value must be traced from generation through to the subprocess-output trust check; the same uuid.uuid7() API is used benignly elsewhere in the file (FastMCP naming), so distinguishing requires the surrounding usage context."),
    "CASE-0002": ("pattern", "structural",
                  "eval() applied directly to a request field; self-contained one-line sink, no cross-variable tracing needed."),
    "CASE-0003": ("pattern", "structural",
                  "eval() applied directly to log-derived text; self-contained sink."),
    "CASE-0004": ("taint", "context_heavy",
                  "Unredacted tree data must be traced to the cross-role remote() call; requires knowing which fields are sensitive and the GUEST/HOST trust boundary, not visible from the line alone."),
    "CASE-0005": ("pattern", "structural",
                  "mark_safe() wrapping an unescaped %-interpolated value is a self-contained syntactic idiom."),
    "CASE-0006": ("pattern", "context_heavy",
                  "The flaw is a wrong dependency choice (get_current_user vs get_current_active_superuser); recognizing it as wrong requires comparing against sibling endpoints' correct usage in the same file."),
    "CASE-0007": ("pattern", "structural",
                  "log.info() called directly on the config object; self-contained sink."),
    "CASE-0008": ("taint", "structural",
                  "Unsanitized app_name flows from the route parameter directly into a path join within a single short function."),
    "CASE-0009": ("pattern", "structural",
                  "Raw bytes embedded directly in an exception constructor; self-contained."),
    "CASE-0010": ("pattern", "context_heavy",
                  "The flaw is an omission (missing removeShare() calls) rather than a bad line; detecting it requires reasoning about the whole script's absence of a hardening step, not a single matchable line."),
    "CASE-0011": ("pattern", "context_heavy",
                  "The flaw is a missing string literal in a ~90-entry denylist; recognizing the omission requires the full list as context, not a local pattern."),
    "CASE-0012": ("pattern", "structural",
                  "Self-recursive call with no depth bound is a locally-recognizable structural idiom."),
    "CASE-0013": ("taint", "context_heavy",
                  "Missing JNDI validation before use; recognizing the gap requires comparing against the sibling endpoint pattern and knowing what a validation call should look like."),
    "CASE-0014": ("pattern", "structural",
                  "createTempFile() + delete() + mkdir() is a well-known, locally-recognizable insecure idiom."),
    "CASE-0015": ("pattern", "context_heavy",
                  "The flaw is using the wrong encoder function for the rendering context (HTML vs JS); the template's actual rendering context isn't visible in this file, so recognizing the mismatch needs external/contextual knowledge."),
    "CASE-0016": ("pattern", "structural",
                  "String concatenation directly into a SQL string is a self-contained syntactic pattern."),
    "CASE-0017": ("pattern", "structural",
                  "Both compared values embedded directly in one exception constructor call."),
    "CASE-0018": ("taint", "context_heavy",
                  "The flaw is a missing session-invalidation step before an unrelated setAuthentication() call; recognizing the gap requires understanding the login-flow ordering, not a single bad line."),
    "CASE-0019": ("taint", "context_heavy",
                  "String-based canonical-path prefix containment vs. NIO Path-based containment is a subtle semantic distinction that requires understanding path-traversal semantics, not just spotting an API name."),
    "CASE-0020": ("pattern", "context_heavy",
                  "Plain ant-pattern requestMatchers() vs MvcRequestMatcher is a Spring-MVC-specific idiom; recognizing the risk requires framework-specific knowledge of DispatcherServlet path-mapping semantics."),
    "CASE-0021": ("pattern", "structural",
                  "Hash-based token generation from semi-public fields is a self-contained, locally-recognizable idiom."),
    "CASE-0022": ("taint", "context_heavy",
                  "Missing validation of a re-exchanged identity against the pre-TLS identity; recognizing the gap requires understanding the two-phase handshake protocol, not a single line."),
    "CASE-0023": ("pattern", "context_heavy",
                  "The flaw is a field's inclusion in an unvalidated bulk-save selector list; recognizing it requires reading the whole selector list as context."),
    "CASE-0024": ("pattern", "structural",
                  "new Function() applied directly to parsed response data; self-contained sink, same shape as eval()."),
    "CASE-0025": ("pattern", "structural",
                  "Missing '--' separator and dash-prefix rejection before spawnSync(); self-contained within the function."),
    "CASE-0026": ("pattern", "context_heavy",
                  "{} vs Object.create(null) is a one-line idiom, but recognizing it as security-relevant requires knowing the object is later indexed with a dynamic, externally-controlled key elsewhere in the file."),
    "CASE-0027": ("taint", "context_heavy",
                  "A validate-then-transform ordering bug across two statements; requires understanding platform-specific path.normalize() semantics to see why the order matters."),
    "CASE-0028": ("pattern", "structural",
                  "Missing Secure attribute on a cookie-string assignment; self-contained."),
    "CASE-0029": ("pattern", "structural",
                  "The vulnerable regex literal itself is the defect; identifiable without tracing any data flow."),
    "CASE-0030": ("pattern", "structural",
                  "Missing length guard before a regex match call; self-contained within the function."),
    "CASE-0031": ("taint", "context_heavy",
                  "Missing authorization check before returning a fetched record; recognizing the gap requires understanding the procedure's intended access-control semantics, not just the query itself."),
    "CASE-0032": ("taint", "context_heavy",
                  "Missing await of a verification promise before submitting credentials; a concurrency/ordering issue that requires understanding the two-phase TLS handshake, not a local pattern."),
    "CASE-0033": ("pattern", "structural",
                  "http:// vs https:// literal in a URL constructor call; self-contained."),
    "CASE-0034": ("pattern", "context_heavy",
                  "Permission.Public vs [] in a decorator's create: field; recognizing the risk requires domain knowledge of what public creation of a User entity implies."),
    "CASE-0035": ("taint", "context_heavy",
                  "Missing explicit rejection when no password is set, combined with a dummy-password fallback; requires tracing the interaction between two branches to see the bypass."),
    "CASE-0036": ("taint", "structural",
                  "Attacker-controlled tool-call argument flows directly into a shell command string within a single case block."),
    "CASE-0037": ("pattern", "structural",
                  "Missing filter for specific dangerous string literals (__proto__/constructor/prototype) in a segment-building loop; self-contained."),
    "CASE-0038": ("taint", "structural",
                  "A sanitize-then-transform ordering bug across two statements within one short function."),
    "CASE-0039": ("taint", "structural",
                  "Unsanitized host parameter flows directly into a shell command string within a single function."),
    "CASE-0040": ("taint", "context_heavy",
                  "An unsanitized config-derived value is concatenated into a cache identifier; recognizing the risk requires tracing that identifier's later use as a filesystem path, not visible in this fragment alone."),
}


def compute_diff_stats(diff_text: str) -> dict:
    files_changed = len(re.findall(r"^diff --git", diff_text, re.MULTILINE))
    added = len(re.findall(r"^\+(?!\+\+)", diff_text, re.MULTILINE))
    removed = len(re.findall(r"^-(?!--)", diff_text, re.MULTILINE))
    return {"changed_files": files_changed, "lines_added": added, "lines_removed": removed, "lines_changed_total": added + removed}


def main():
    out_dir = BENCH_DIR / "difficulty"
    out_dir.mkdir(exist_ok=True)
    summary = []

    for case_id, (pattern_or_taint, struct_or_context, rationale) in JUDGMENT.items():
        case_dir = BENCH_DIR / "cases" / case_id
        metadata = json.loads((case_dir / "metadata.json").read_text())
        context = json.loads((BENCH_DIR / "model_context" / f"{case_id}.json").read_text())
        diff_stats = compute_diff_stats((case_dir / "patch.diff").read_text())

        vuln_func_chars = len(context["vulnerable_function"])
        vuln_func_lines = context["vulnerable_function"].count("\n") + 1

        result = {
            "case_id": case_id,
            "language": metadata["language"],
            "cwe_ids": metadata["cwe_ids"],
            **diff_stats,
            "function_size_chars": vuln_func_chars,
            "function_size_lines": vuln_func_lines,
            "pattern_or_taint": pattern_or_taint,
            "structural_or_context_heavy": struct_or_context,
            "classification_rationale": rationale,
            "supported_status": metadata["semgrep_representability"],
        }
        out_path = out_dir / f"{case_id}.json"
        out_path.write_text(json.dumps(result, indent=2) + "\n")
        summary.append(result)

    # aggregate summary
    from collections import Counter
    print("Total cases:", len(summary))
    print("By language:", Counter(s["language"] for s in summary))
    print("By pattern_or_taint:", Counter(s["pattern_or_taint"] for s in summary))
    print("By structural_or_context_heavy:", Counter(s["structural_or_context_heavy"] for s in summary))
    print("By supported_status:", Counter(s["supported_status"] for s in summary))
    print("Function size (lines) min/max/avg:",
          min(s["function_size_lines"] for s in summary),
          max(s["function_size_lines"] for s in summary),
          sum(s["function_size_lines"] for s in summary) / len(summary))

    (BENCH_DIR / "difficulty_summary.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
