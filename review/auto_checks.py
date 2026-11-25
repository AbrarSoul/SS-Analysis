#!/usr/bin/env python3
"""
Stage 1 automated pre-checks for the ground-truth review.

Runs cheap, mechanical checks on every case folder and writes one CSV row per
case plus a summary. It never changes any case file.

Usage:
  python3 auto_checks.py --cases benchmark/cases --out review/auto_checks
  python3 auto_checks.py --cases benchmark/cases --out review/auto_checks \
      --reference benchmark/all_cases_reference.csv --only-status eligible,excluded(upstream-fix-bypassable)
  python3 auto_checks.py ... --fetch      # also compare files 1-2 with GitHub (checks A/B)

Flags written per case (empty = no problem found):
  missing_files        sample or support files absent
  hash_mismatch        file SHA-256 differs from metadata artifact_hashes
  github_A / github_B  (only with --fetch) source differs from GitHub
  compile_<sample>     new compile/syntax errors in a generated sample that the
                       original vulnerable_source does not have
  stub_<sample>        generated sample looks like a stub (omitted body, TODO...)
  leak_<sample>        a comment in a generated sample may reveal its label
  identical_<sample>   generated variant is identical to its source file
  fix_outside_lines    patch.diff changes lines outside vulnerable_lines
  meta_vs_reference    metadata.json disagrees with all_cases_reference.csv
"""
import argparse, csv, hashlib, json, os, re, shutil, subprocess, sys, tempfile, urllib.request
from pathlib import Path

SAMPLES = ["vulnerable_source", "patched_source", "variant_vulnerable_01",
           "variant_vulnerable_02", "variant_safe_01", "benign_lookalike"]
GENERATED = SAMPLES[2:]
STUB_RE = re.compile(r"(omitted|not implemented|TODO|FIXME|placeholder|stub\b|\.\.\.\s*$|"
                     r"implementation\s+(omitted|elided|left out))", re.I | re.M)
LEAK_RE = re.compile(r"(\bsafe\b|\bunsafe\b|vulnerab|\btrusted\b|untrusted|never supplied|"
                     r"sanitiz|\bfix(ed)?\b|exploit|attack|malicious|CVE-|CWE-)", re.I)
COMMENT_RE = {
    "java": re.compile(r"//[^\n]*|/\*.*?\*/", re.S),
    "javascript": re.compile(r"//[^\n]*|/\*.*?\*/", re.S),
    "typescript": re.compile(r"//[^\n]*|/\*.*?\*/", re.S),
    "python": re.compile(r"#[^\n]*|\"\"\".*?\"\"\"|'''.*?'''", re.S),
}
EXT = {"java": [".java"], "python": [".py"], "javascript": [".js", ".mjs", ".cjs", ".jsx"],
       "typescript": [".ts", ".tsx"]}


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def find_sample(case_dir, stem):
    hits = [p for p in case_dir.glob(stem + ".*") if not p.name.startswith("._")]
    return hits[0] if hits else None


# ---------- compile / syntax checks: report only errors the original doesn't have ----------
def java_errors(path):
    if not shutil.which("javac"):
        return None
    src = path.read_text(errors="replace")
    m = re.search(r"public\s+(?:final\s+|abstract\s+)*(?:class|interface|enum|record)\s+(\w+)", src)
    name = (m.group(1) if m else path.stem) + ".java"
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / name
        f.write_text(src)
        # Empty placeholder classes for the project's own imports. Without them javac stops at
        # "package does not exist" and never checks method calls (e.g. a renamed method).
        stubs = []
        for pkg, cls in re.findall(r"^import\s+(?!static)([\w.]+)\.([A-Z]\w*)\s*;", src, re.M):
            if pkg.startswith(("java.", "javax.", "jdk.", "sun.")):
                continue
            sp = Path(d, "stubs", *pkg.split("."), cls + ".java")
            sp.parent.mkdir(parents=True, exist_ok=True)
            sp.write_text(f"package {pkg};\npublic class {cls} {{}}\n")
            stubs.append(str(sp))
        r = subprocess.run(["javac", "-proc:none", "-Xmaxerrs", "500", "-d", str(Path(d, "out")),
                            str(f), *stubs], capture_output=True, text=True)
    errs, cur = set(), None
    for line in r.stderr.splitlines():
        mm = re.match(r".*?\.java:\d+: error: (.*)", line)
        if mm:
            cur = mm.group(1).strip(); errs.add(cur)
        elif cur and line.strip().startswith("symbol:"):
            errs.discard(cur); cur = cur + " | " + line.strip(); errs.add(cur)
    return errs


def python_errors(path):
    r = subprocess.run([sys.executable, "-m", "py_compile", str(path)], capture_output=True, text=True)
    errs = set()
    if r.returncode:
        errs.add("syntax: " + r.stderr.strip().splitlines()[-1])
    try:
        import pyflakes  # noqa
        r = subprocess.run([sys.executable, "-m", "pyflakes", str(path)], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if "undefined name" in line:
                errs.add(re.sub(r"^.*?:\d+:\d+:?\s*", "", line))
    except ImportError:
        pass
    return errs


def js_errors(path, lang):
    if lang == "typescript":
        if not shutil.which("tsc"):
            return None
        r = subprocess.run(["tsc", "--noEmit", "--noResolve", "--isolatedModules", "--skipLibCheck",
                            str(path)], capture_output=True, text=True)
        return {re.sub(r"^.*?\(\d+,\d+\):\s*", "", l) for l in r.stdout.splitlines()
                if "error TS" in l and "TS2307" not in l}  # ignore "cannot find module"
    if not shutil.which("node"):
        return None
    r = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
    if r.returncode and "SyntaxError" in r.stderr:
        return {"syntax: " + [l for l in r.stderr.splitlines() if "SyntaxError" in l][0]}
    return set()


def compile_errors(path, lang):
    if lang == "java":
        return java_errors(path)
    if lang == "python":
        return python_errors(path)
    if lang in ("javascript", "typescript"):
        return js_errors(path, lang)
    return None


# ---------- patch coverage ----------
def changed_old_lines(diff_text):
    """Line numbers in the OLD (vulnerable) file touched by the patch.
    Pure insertions are attributed to the line just before them."""
    lines, old = [], None
    for l in diff_text.splitlines():
        m = re.match(r"@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@", l)
        if m:
            old = int(m.group(1)); continue
        if old is None or l.startswith(("---", "+++")):
            continue
        if l.startswith("-"):
            lines.append(old); old += 1
        elif l.startswith("+"):
            lines.append(max(old - 1, 1))
        else:
            old += 1
    return sorted(set(lines))


def ranges_from(vl):
    """vulnerable_lines may be [start, end], [[s,e],...], or a list of single lines."""
    if not vl:
        return []
    if all(isinstance(x, list) for x in vl):
        return [(int(a), int(b)) for a, b in vl]
    if len(vl) == 2 and all(isinstance(x, int) for x in vl) and vl[1] >= vl[0]:
        return [(vl[0], vl[1])]
    return [(int(x), int(x)) for x in vl]


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()


def check_case(case_dir, ref_row, do_fetch):
    flags, notes = [], []
    meta_p = case_dir / "metadata.json"
    if not meta_p.exists():
        return ["missing_files"], ["no metadata.json"], {}
    meta = json.loads(meta_p.read_text())
    lang = meta.get("language", "").lower()
    files = {s: find_sample(case_dir, s) for s in SAMPLES}
    missing = [s for s, p in files.items() if p is None]
    if not (case_dir / "patch.diff").exists():
        missing.append("patch.diff")
    if missing:
        flags.append("missing_files"); notes.append("missing: " + ",".join(missing))

    # hashes (metadata.json can't contain its own hash, so it is skipped)
    for key, h in (meta.get("artifact_hashes") or {}).items():
        p = case_dir / Path(key).name
        if p.name == "metadata.json" or not p.exists() or not key.startswith("cases/"):
            continue
        if sha256(p) != h:
            flags.append("hash_mismatch"); notes.append(f"hash differs: {p.name}")

    # A/B against GitHub
    if do_fetch and meta.get("repository") and meta.get("changed_file"):
        base = f"https://raw.githubusercontent.com/{meta['repository']}"
        for tag, commit, s in (("A", "vulnerable_commit", "vulnerable_source"),
                               ("B", "fixed_commit", "patched_source")):
            if files.get(s) is None:
                continue
            try:
                remote = fetch(f"{base}/{meta[commit]}/{meta['changed_file']}")
                if remote != files[s].read_bytes():
                    flags.append(f"github_{tag}"); notes.append(f"{s} differs from GitHub")
            except Exception as e:
                flags.append(f"github_{tag}"); notes.append(f"{tag}: fetch failed ({e.__class__.__name__})")

    # compile / syntax: only errors that the original does not already have
    base_errs = compile_errors(files["vulnerable_source"], lang) if files.get("vulnerable_source") else None
    for s in GENERATED + ["patched_source"]:
        p = files.get(s)
        if p is None:
            continue
        errs = compile_errors(p, lang)
        if errs is None:
            notes.append(f"{s}: compiler not available"); continue
        new = errs - (base_errs or set())
        if new:
            flags.append(f"compile_{s}"); notes.append(f"{s}: " + "; ".join(sorted(new))[:300])

    # stubs, label leaks, identical copies
    crx = COMMENT_RE.get(lang)
    for s in GENERATED:
        p = files.get(s)
        if p is None:
            continue
        txt = p.read_text(errors="replace")
        if STUB_RE.search(txt):
            flags.append(f"stub_{s}"); notes.append(f"{s}: '{STUB_RE.search(txt).group(0).strip()}'")
        if crx:
            hits = {m.group(0).lower() for c in crx.findall(txt) for m in LEAK_RE.finditer(c)}
            if hits:
                flags.append(f"leak_{s}"); notes.append(f"{s} comment words: {', '.join(sorted(hits))}")
        src = files["vulnerable_source"] if s.startswith("variant_vulnerable") else None
        if src and src.read_bytes() == p.read_bytes():
            flags.append(f"identical_{s}")

    # does the real fix touch lines outside vulnerable_lines?
    if (case_dir / "patch.diff").exists():
        touched = changed_old_lines((case_dir / "patch.diff").read_text(errors="replace"))
        rngs = ranges_from(meta.get("vulnerable_lines"))
        outside = [n for n in touched if not any(a - 2 <= n <= b + 2 for a, b in rngs)]
        if rngs and outside:
            flags.append("fix_outside_lines")
            notes.append(f"vulnerable_lines {rngs}; patch also touches old lines {outside}")

    # metadata vs reference CSV
    if ref_row:
        for k in ("cve_id", "vulnerable_commit", "fixed_commit", "repository", "changed_file"):
            if ref_row.get(k) and str(meta.get(k, "")) != ref_row[k]:
                flags.append("meta_vs_reference"); notes.append(f"{k}: metadata={meta.get(k)} csv={ref_row[k]}")

    info = {"language": lang, "cve_id": meta.get("cve_id", ""), "cwe_ids": ";".join(meta.get("cwe_ids", [])),
            "auto_locate_confidence": meta.get("auto_locate_confidence", "")}
    return sorted(set(flags)), notes, info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", required=True, help="folder holding CASE-XXXX folders")
    ap.add_argument("--out", required=True, help="output folder")
    ap.add_argument("--reference", help="all_cases_reference.csv (to add status and filter)")
    ap.add_argument("--only-status", help="comma list of status prefixes to include, e.g. eligible")
    ap.add_argument("--fetch", action="store_true", help="compare files 1-2 with GitHub (needs internet)")
    a = ap.parse_args()

    ref = {}
    if a.reference:
        with open(a.reference, newline="") as f:
            ref = {r["case_id"]: r for r in csv.DictReader(f)}
    wanted = [s.strip() for s in a.only_status.split(",")] if a.only_status else None

    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    rows = []
    for case_dir in sorted(p for p in Path(a.cases).iterdir() if p.is_dir() and p.name.startswith("CASE-")):
        r = ref.get(case_dir.name, {})
        status = r.get("status", "")
        if wanted and not any(status.startswith(w) for w in wanted):
            continue
        flags, notes, info = check_case(case_dir, r, a.fetch)
        rows.append({"case_id": case_dir.name, "status": status,
                     "priority_38": "yes" if "priority-audit-38" in status else "",
                     **info, "n_flags": len(flags), "flags": ";".join(flags), "notes": " | ".join(notes)})
        print(f"{case_dir.name}: {len(flags)} flag(s) {';'.join(flags)}")

    cols = ["case_id", "status", "priority_38", "language", "cve_id", "cwe_ids",
            "auto_locate_confidence", "n_flags", "flags", "notes"]
    with open(out / "auto_checks.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader(); w.writerows(rows)

    counts = {}
    for r in rows:
        for fl in filter(None, r["flags"].split(";")):
            key = re.sub(r"_(vulnerable_source|patched_source|variant_\w+|benign_lookalike)$", "_<sample>", fl)
            counts[key] = counts.get(key, 0) + 1
    with open(out / "summary.txt", "w") as f:
        f.write(f"cases checked: {len(rows)}\ncases with no flags: {sum(1 for r in rows if not r['flags'])}\n\n")
        for k, v in sorted(counts.items(), key=lambda x: -x[1]):
            f.write(f"{v:4d}  {k}\n")
    print("\n" + (out / "summary.txt").read_text())


if __name__ == "__main__":
    main()
