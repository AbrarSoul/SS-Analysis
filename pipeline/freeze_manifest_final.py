"""
Section 8 Step 7 for the 300-case FINAL dataset (Phase 4): assigns stable
case IDs, consolidates the four selection batches (original + three
top-ups) into the same benchmark/cases/, benchmark/model_context/, and
benchmark/difficulty/ directories the pilot already uses, and freezes the
result with per-artifact and dataset-level SHA-256 hashes -- same approach
as freeze_manifest.py (the pilot's own Step 7), extended to also do the
case-ID assignment and directory consolidation the pilot didn't need
(pilot IDs were already assigned before its own Step 7 ran).

Case IDs continue from where the pilot left off: CASE-0041 onward, never
CASE-0001..CASE-0040 again, so pilot and final cases can never collide or
be confused for one another. Assigned in a fixed, reproducible order
(sorted by original filename-derived case_id, batch by batch) rather than
anything nondeterministic.

Known gaps, deliberately left unpopulated rather than fabricated -- same
principle as the pilot's own freeze, extended by three more fields this
partition specifically deferred (Section 12.10/12.11 of the Implementation
Log): pattern_or_taint, structural_or_context_heavy (context_complexity),
and supported_status (semgrep_representability) all require the same
hands-on per-case understanding Section 9's test-bundle construction will
produce; filling them in now would mean fabricating 302 shallow judgments.
"""
import hashlib
import json
import shutil
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmark"

STEP3_DIRS = {
    "final": BENCH_DIR / "step3_repo_states_final",
    "topup": BENCH_DIR / "step3_repo_states_topup",
    "topup2": BENCH_DIR / "step3_repo_states_topup2",
    "topup3": BENCH_DIR / "step3_repo_states_topup3",
    "topup4": BENCH_DIR / "step3_repo_states_topup4",
    "topup5": BENCH_DIR / "step3_repo_states_topup5",
    "topup6": BENCH_DIR / "step3_repo_states_topup6",
    "topup7": BENCH_DIR / "step3_repo_states_topup7",
    "topup8": BENCH_DIR / "step3_repo_states_topup8",
    "topup9": BENCH_DIR / "step3_repo_states_topup9",
    "topup10": BENCH_DIR / "step3_repo_states_topup10",
    "topup11": BENCH_DIR / "step3_repo_states_topup11",
    "topup12": BENCH_DIR / "step3_repo_states_topup12",
    "topup13": BENCH_DIR / "step3_repo_states_topup13",
    "topup14": BENCH_DIR / "step3_repo_states_topup14",
    "topup15": BENCH_DIR / "step3_repo_states_topup15",
    "topup16": BENCH_DIR / "step3_repo_states_topup16",
    "topup17": BENCH_DIR / "step3_repo_states_topup17",
    "topup18": BENCH_DIR / "step3_repo_states_topup18",
    "topup19": BENCH_DIR / "step3_repo_states_topup19",
    "topup20": BENCH_DIR / "step3_repo_states_topup20",
    "topup21": BENCH_DIR / "step3_repo_states_topup21",
    "topup22": BENCH_DIR / "step3_repo_states_topup22",
    "topup23": BENCH_DIR / "step3_repo_states_topup23",
    "topup24": BENCH_DIR / "step3_repo_states_topup24",
    "topup25": BENCH_DIR / "step3_repo_states_topup25",
    "topup26": BENCH_DIR / "step3_repo_states_topup26",
    "topup27": BENCH_DIR / "step3_repo_states_topup27",
    "topup28": BENCH_DIR / "step3_repo_states_topup28",
    "topup29": BENCH_DIR / "step3_repo_states_topup29",
    "topup30": BENCH_DIR / "step3_repo_states_topup30",
    "topup31": BENCH_DIR / "step3_repo_states_topup31",
    "topup32": BENCH_DIR / "step3_repo_states_topup32",
    "topup33": BENCH_DIR / "step3_repo_states_topup33",
    "topup34": BENCH_DIR / "step3_repo_states_topup34",
    "topup35": BENCH_DIR / "step3_repo_states_topup35",
    "topup36": BENCH_DIR / "step3_repo_states_topup36",
    "topup37": BENCH_DIR / "step3_repo_states_topup37",
    "topup38": BENCH_DIR / "step3_repo_states_topup38",
    "topup39": BENCH_DIR / "step3_repo_states_topup39",
    "topup40": BENCH_DIR / "step3_repo_states_topup40",
}
CONTEXT_DIRS = {
    "final": BENCH_DIR / "model_context_final",
    "topup": BENCH_DIR / "model_context_topup",
    "topup2": BENCH_DIR / "model_context_topup2",
    "topup3": BENCH_DIR / "model_context_topup3",
    "topup4": BENCH_DIR / "model_context_topup4",
    "topup5": BENCH_DIR / "model_context_topup5",
    "topup6": BENCH_DIR / "model_context_topup6",
    "topup7": BENCH_DIR / "model_context_topup7",
    "topup8": BENCH_DIR / "model_context_topup8",
    "topup9": BENCH_DIR / "model_context_topup9",
    "topup10": BENCH_DIR / "model_context_topup10",
    "topup11": BENCH_DIR / "model_context_topup11",
    "topup12": BENCH_DIR / "model_context_topup12",
    "topup13": BENCH_DIR / "model_context_topup13",
    "topup14": BENCH_DIR / "model_context_topup14",
    "topup15": BENCH_DIR / "model_context_topup15",
    "topup16": BENCH_DIR / "model_context_topup16",
    "topup17": BENCH_DIR / "model_context_topup17",
    "topup18": BENCH_DIR / "model_context_topup18",
    "topup19": BENCH_DIR / "model_context_topup19",
    "topup20": BENCH_DIR / "model_context_topup20",
    "topup21": BENCH_DIR / "model_context_topup21",
    "topup22": BENCH_DIR / "model_context_topup22",
    "topup23": BENCH_DIR / "model_context_topup23",
    "topup24": BENCH_DIR / "model_context_topup24",
    "topup25": BENCH_DIR / "model_context_topup25",
    "topup26": BENCH_DIR / "model_context_topup26",
    "topup27": BENCH_DIR / "model_context_topup27",
    "topup28": BENCH_DIR / "model_context_topup28",
    "topup29": BENCH_DIR / "model_context_topup29",
    "topup30": BENCH_DIR / "model_context_topup30",
    "topup31": BENCH_DIR / "model_context_topup31",
    "topup32": BENCH_DIR / "model_context_topup32",
    "topup33": BENCH_DIR / "model_context_topup33",
    "topup34": BENCH_DIR / "model_context_topup34",
    "topup35": BENCH_DIR / "model_context_topup35",
    "topup36": BENCH_DIR / "model_context_topup36",
    "topup37": BENCH_DIR / "model_context_topup37",
    "topup38": BENCH_DIR / "model_context_topup38",
    "topup39": BENCH_DIR / "model_context_topup39",
    "topup40": BENCH_DIR / "model_context_topup40",
}
DIFFICULTY_DIR = BENCH_DIR / "difficulty_final"  # single dir, batch already merged by classify_difficulty_final.py

CASES_DIR = BENCH_DIR / "cases"
SHARED_CONTEXT_DIR = BENCH_DIR / "model_context"
SHARED_DIFFICULTY_DIR = BENCH_DIR / "difficulty"

EXT_BY_LANG = {"python": "py", "java": "java", "javascript": "js", "typescript": "ts"}

KNOWN_UNPOPULATED_SCHEMA_FIELDS = [
    "ghsa_id", "advisory_date", "repository_license", "source_urls",
]

START_ID = 41  # continues from the pilot's CASE-0001..CASE-0040


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def find_vulnerable_lines(vuln_source_path: Path, vuln_function_text: str):
    source = vuln_source_path.read_text()
    probe = vuln_function_text.split("... [TRUNCATED")[0][:200]
    try:
        start_char = source.index(probe)
    except ValueError:
        return None
    start_line = source.count("\n", 0, start_char) + 1
    end_line = start_line + vuln_function_text.count("\n")
    return [start_line, end_line]


def main():
    # --- gather every surviving case across all four batches, sorted for
    # a reproducible ID assignment order ---
    # Re-running an extract_context_* script regenerates a context file for
    # EVERY step-3 case, including ones later excluded (language-balance
    # trims, Section 9 review exclusions). exclusion_log.csv is the single
    # source of truth for those, so honour it here (found live: re-running
    # extraction resurrected 15 excluded cases).
    import csv
    # step5_jsts_balance_trim (round 1) was superseded by the later trim
    # rounds: 3 of its 8 entries are legitimately part of the final set, so
    # that one stage is not authoritative.
    excluded_ids = {r["case_id"] for r in csv.DictReader((BENCH_DIR / "exclusion_log.csv").open())
                    if r["stage"] != "step5_jsts_balance_trim"}
    # Hand-curated cases (benchmark/hand_curations.json) carry a different
    # original_source_case_id after correction; map old -> new so the
    # occupant check below does not wipe their Section 9 bundle files.
    hand_curations = json.loads((BENCH_DIR / "hand_curations.json").read_text())
    hand_new_id = {h["old_original_source_case_id"]: h.get("new_original_source_case_id")
                   for h in hand_curations if "old_original_source_case_id" in h}  # "retarget" entries keep their original id

    # Section 9 judgement labels (pattern_or_taint, context_complexity,
    # semgrep_representability), keyed by ORIGINAL pipeline id so they
    # survive case-id shifts. See benchmark/labels_final.json.
    labels = json.loads((BENCH_DIR / "labels_final.json").read_text())["labels"]

    all_cases = []  # (original_case_id, batch)
    for batch, context_dir in CONTEXT_DIRS.items():
        for f in sorted(context_dir.glob("*.json")):
            if f.stem in excluded_ids:
                continue
            all_cases.append((f.stem, batch))
    all_cases.sort(key=lambda t: t[0])

    print(f"Total surviving cases across all batches: {len(all_cases)}")

    # Case ids are PINNED in benchmark/case_id_registry.json (original pipeline
    # id -> CASE-XXXX), assigned once and never renumbered. Assigning ids by
    # sorted position (the old behaviour) renumbered every later case
    # whenever any case was excluded or added, which silently invalidated
    # the per-case Section 9 bundles built under the old ids (found live in
    # Sections 12.14-12.16). A retired case keeps its id forever (a gap), and
    # a new case gets max(id)+1.
    registry_path = BENCH_DIR / "case_id_registry.json"
    if not registry_path.exists():
        raise SystemExit("benchmark/case_id_registry.json is missing; refusing to fall back to position-based ids")
    registry = json.loads(registry_path.read_text())["ids"]
    next_num = max(int(v[5:]) for v in registry.values()) + 1
    surviving = {orig for orig, _ in all_cases}
    for orig_case_id, _ in all_cases:  # already sorted by original id -> deterministic allocation
        if orig_case_id not in registry:
            registry[orig_case_id] = f"CASE-{next_num:04d}"
            next_num += 1
    retired = {o: cid for o, cid in registry.items() if o not in surviving}
    for orig, cid in retired.items():
        stale = [CASES_DIR / cid, SHARED_CONTEXT_DIR / f"{cid}.json", SHARED_DIFFICULTY_DIR / f"{cid}.json"]
        for s_ in stale:
            if s_.is_dir():
                shutil.rmtree(s_)
            elif s_.exists():
                s_.unlink()
    all_cases.sort(key=lambda t: registry[t[0]])
    if len({registry[o] for o, _ in all_cases}) != len(all_cases):
        raise SystemExit("duplicate case ids in registry")

    frozen_records = []
    case_level_hashes = {}

    for i, (orig_case_id, batch) in enumerate(all_cases):
        new_case_id = registry[orig_case_id]
        step3_dir = STEP3_DIRS[batch] / orig_case_id
        context_path = CONTEXT_DIRS[batch] / f"{orig_case_id}.json"
        difficulty_path = DIFFICULTY_DIR / f"{orig_case_id}.json"

        step3_metadata = json.loads((step3_dir / "metadata.json").read_text())
        context = json.loads(context_path.read_text())
        difficulty = json.loads(difficulty_path.read_text())
        language = step3_metadata["language"]
        ext = EXT_BY_LANG[language]

        # --- consolidate into benchmark/cases/CASE-0XXX/, same layout the
        # pilot's own cases already use ---
        case_dir = CASES_DIR / new_case_id
        # A re-freeze can reassign which original case a given CASE-00XX id
        # points to (the id is assigned by sorted position among survivors,
        # which shifts whenever the survivor set itself changes -- e.g.
        # topup4/topup5 added new MaxKB candidates that sort ahead of
        # 9001/copyparty, pushing it from CASE-0042 to CASE-0043). Without
        # this check, the OLD occupant's files -- including hand-built
        # Section 9 bundle files (variant_vulnerable_01.py etc.), which
        # this script never writes and so never overwrites -- silently
        # stayed behind, now orphaned and misattributed to whatever new
        # case reused that directory. Found live exactly this way on
        # CASE-0042/CASE-0043 in this session. Same "a run's output should
        # exactly reflect that run's own decisions, not accumulate stale
        # leftovers" principle as extract_context_final.py's own
        # output-directory-clearing fix (Section 12.11) -- scoped to only
        # wipe when the occupant actually changed, so legitimate same-case
        # reruns (e.g. CASE-0041 stayed CASE-0041) keep their Section 9
        # work untouched.
        existing_metadata_path = case_dir / "metadata.json"
        if existing_metadata_path.exists():
            existing_original_id = json.loads(existing_metadata_path.read_text()).get("original_source_case_id")
            if existing_original_id not in (orig_case_id, hand_new_id.get(orig_case_id)):
                shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy(step3_dir / "vulnerable_source", case_dir / f"vulnerable_source.{ext}")
        shutil.copy(step3_dir / "patched_source", case_dir / f"patched_source.{ext}")
        shutil.copy(step3_dir / "patch.diff", case_dir / "patch.diff")

        first_line = context["vulnerable_function"].splitlines()[0].strip() if context["vulnerable_function"] else ""
        vulnerable_lines = find_vulnerable_lines(case_dir / f"vulnerable_source.{ext}", context["vulnerable_function"])

        case_metadata = {
            "case_id": new_case_id,
            "original_source_case_id": orig_case_id,
            "selection_batch": batch,
            "cve_id": step3_metadata.get("cve_ids", [None])[0],
            "cve_ids_all": step3_metadata.get("cve_ids", []),
            "ghsa_id": None,
            "cwe_ids": step3_metadata.get("cwe_ids", []),
            "language": language,
            "repository": step3_metadata["repository"],
            "repository_url": step3_metadata.get("repository_url"),
            "vulnerable_commit": step3_metadata["vulnerable_commit"],
            "fixed_commit": step3_metadata["fixed_commit"],
            "changed_file": step3_metadata["changed_file"],
            "changed_function": first_line,
            "vulnerable_lines": vulnerable_lines,
            "context_complexity": (labels.get(orig_case_id) or {}).get("structural_or_context_heavy"),
            "semgrep_representability": (labels.get(orig_case_id) or {}).get("semgrep_representability"),
            "pattern_or_taint": (labels.get(orig_case_id) or {}).get("pattern_or_taint"),
            "patch_size_added": difficulty["lines_added"],
            "patch_size_deleted": difficulty["lines_removed"],
            "auto_locate_confidence": context.get("auto_locate_confidence"),
            "advisory_date": None,
            "repository_license": None,
            "split": "final",
            "source_urls": [],
        }
        (case_dir / "metadata.json").write_text(json.dumps(case_metadata, indent=2) + "\n")

        # --- copy Step 5/6 output into the SHARED dirs the pilot already
        # uses, under the new case_id, so downstream tooling (case_loader.py,
        # run_generation.py) needs no pilot-vs-final special-casing ---
        context_out = dict(context)
        context_out["case_id"] = new_case_id
        (SHARED_CONTEXT_DIR / f"{new_case_id}.json").write_text(json.dumps(context_out, indent=2) + "\n")

        difficulty_out = dict(difficulty)
        difficulty_out["case_id"] = new_case_id
        lab = labels.get(orig_case_id)
        if lab is None:  # new case whose Section 9 bundle/label is not written yet
            print(f"WARNING: no label for {new_case_id} ({orig_case_id}); classification fields left null")
            lab = {"pattern_or_taint": None, "structural_or_context_heavy": None,
                   "semgrep_representability": None, "rationale": None}
        difficulty_out["pattern_or_taint"] = lab["pattern_or_taint"]
        difficulty_out["structural_or_context_heavy"] = lab["structural_or_context_heavy"]
        difficulty_out["supported_status"] = lab["semgrep_representability"]
        difficulty_out["classification_rationale"] = lab["rationale"]
        difficulty_out.pop("classification_pending_reason", None)
        (SHARED_DIFFICULTY_DIR / f"{new_case_id}.json").write_text(json.dumps(difficulty_out, indent=2) + "\n")

        # --- hash every artifact this SCRIPT itself writes -- deliberately
        # NOT a case_dir.rglob("*") over whatever else happens to be
        # sitting in the directory. Section 9's per-case test-bundle files
        # (variant_vulnerable_01.py, benign_lookalike.py, ...) live in this
        # same case_dir once built, but Section 9 happens AFTER Step 7
        # freezing in the design doc's own ordering -- a frozen hash that
        # silently shifts depending on how much Section 9 work happens to
        # exist yet defeats the point of freezing. Enumerating the known,
        # fixed set of files this step writes keeps the frozen hash stable
        # regardless of Section 9's progress.
        artifact_hashes = {}
        for f in [case_dir / f"vulnerable_source.{ext}", case_dir / f"patched_source.{ext}",
                  case_dir / "patch.diff", case_dir / "metadata.json"]:
            rel = str(f.relative_to(BENCH_DIR))
            artifact_hashes[rel] = sha256_file(f)
        for extra_path in [SHARED_CONTEXT_DIR / f"{new_case_id}.json", SHARED_DIFFICULTY_DIR / f"{new_case_id}.json"]:
            rel = str(extra_path.relative_to(BENCH_DIR))
            artifact_hashes[rel] = sha256_file(extra_path)

        case_metadata["artifact_hashes"] = artifact_hashes
        case_hash_input = "\n".join(f"{k}:{v}" for k, v in sorted(artifact_hashes.items()))
        case_level_hash = hashlib.sha256(case_hash_input.encode()).hexdigest()
        case_metadata["case_level_hash"] = case_level_hash
        case_level_hashes[new_case_id] = case_level_hash

        # rewrite metadata.json now that artifact_hashes/case_level_hash are known
        (case_dir / "metadata.json").write_text(json.dumps(case_metadata, indent=2) + "\n")

        frozen_records.append(case_metadata)

    dataset_hash_input = "\n".join(f"{k}:{v}" for k, v in sorted(case_level_hashes.items()))
    dataset_hash = hashlib.sha256(dataset_hash_input.encode()).hexdigest()

    out_path = BENCH_DIR / "manifest_frozen_final.jsonl"
    with out_path.open("w") as f:
        for record in frozen_records:
            f.write(json.dumps(record) + "\n")

    from collections import Counter
    by_lang = Counter(r["language"] for r in frozen_records)

    freeze_record = {
        "partition": "final",
        "case_count": len(frozen_records),
        "case_id_range": [frozen_records[0]["case_id"], frozen_records[-1]["case_id"]],
        "retired_case_ids_gaps": sorted(retired.values()),
        "by_language": dict(by_lang),
        "dataset_hash_sha256": dataset_hash,
        "manifest_file": "manifest_frozen_final.jsonl",
        "known_unpopulated_schema_fields": KNOWN_UNPOPULATED_SCHEMA_FIELDS,
        "note": (
            "pattern_or_taint / context_complexity / semgrep_representability filled from "
            "benchmark/labels_final.json (single-rater judgement made while building each case's "
            "Section 9 bundle; rubric in that file's _meta; see Implementation_Log.md Section 12.18). "
            "Development (50-case multi-agent) partition not curated yet."
        ),
    }
    (BENCH_DIR / "freeze_record_final.json").write_text(json.dumps(freeze_record, indent=2) + "\n")

    registry_path.write_text(json.dumps(
        {"note": "Pinned case ids: original pipeline id -> CASE-XXXX. Never renumber; retired ids stay as gaps.",
         "ids": dict(sorted(registry.items(), key=lambda kv: kv[1]))}, indent=1) + "\n")
    print(f"\nFroze {len(frozen_records)} cases: {frozen_records[0]['case_id']}..{frozen_records[-1]['case_id']} "
          f"({len(retired)} retired ids left as gaps)")
    print(f"By language: {dict(by_lang)}")
    print(f"Dataset hash (final partition): {dataset_hash}")
    print(f"Wrote {out_path}")
    print(f"Wrote {BENCH_DIR / 'freeze_record_final.json'}")
    print(f"Consolidated case directories under {CASES_DIR}")


def new_case_id_range(start, count):
    return f"CASE-{start:04d}..CASE-{start + count - 1:04d}"


if __name__ == "__main__":
    main()
