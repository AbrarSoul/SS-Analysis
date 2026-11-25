"""
Run v2 entrypoint (Research_Log/Run_v2_Specification.md): one command runs the whole experiment.

  .venv/bin/python3 pipeline/run_v2.py --mode real   --run-dir results_v2/<name>
  .venv/bin/python3 pipeline/run_v2.py --mode smoke  --run-dir results_v2_smoke/<name> [--cases 2]
  .venv/bin/python3 pipeline/run_v2.py --mode dryrun --run-dir results_v2_dryrun/<name> [--cases 2]

Modes
  real    the frozen run. Refuses to start unless every freeze check passes (pinned Semgrep, prompt fingerprints,
          every sample file parses, every vulnerable sample has bug lines, models file frozen, tracked files
          unchanged, HEAD tagged run-v2-frozen, API keys present). Results go to results_v2/.
  smoke   real models on a few cases, one repeat, to measure timing and connectivity (checklist item 8). Failed
          freeze checks are printed but allowed. Results go to results_v2_smoke/ and are never analysed
          (analyze_v2 refuses them).
  dryrun  a built-in fake model (no API key, no inference) through every part, with real Semgrep (checklist item 7).

Order and phases: Part I, then stability, then Part II. Within a phase every model works through the cases in
the one seeded order (run_v2_settings.run_order); models run in parallel, at most `max_concurrent_per_host`
episodes at a time per GPT-Lab host. Part II runs the four cells and their repeats case by case, so all cells
share the same time window.

Stop rule (specification section 2): an API failure that outlasts the retries is logged to infra_failures.jsonl
and the episode is left missing; running the same command again resumes and fills only the missing episodes.
Any other error stops the whole run: fix the bug and restart from zero in a NEW run directory. A run directory
can only be resumed with the same code, benchmark, cases and models (checked against its manifest.json).
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parent.parent / "autogrep")]

import run_v2_episode as E  # noqa: E402
import run_v2_probes as P  # noqa: E402
import run_v2_settings as S  # noqa: E402
import semgrep_runner as SR  # noqa: E402
import target_preflight as TP  # noqa: E402
from case_loader import load_case  # noqa: E402
from config import Config  # noqa: E402
from gptlab_config import get_key_for_host, host_base_url  # noqa: E402
from llm_client import LLMClient  # noqa: E402
from location_ranges import load_location_ranges, missing_ranges  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MODELS_FILE = ROOT / "pipeline" / "run_v2_models.json"
FREEZE_TAG = "run-v2-frozen"
MODE_DIRS = {"real": "results_v2", "smoke": "results_v2_smoke", "dryrun": "results_v2_dryrun"}


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def model_key(tag):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", tag)


def sha256_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def benchmark_sha256(cases):
    h = hashlib.sha256()
    for cid in sorted(cases):
        for f in sorted((ROOT / "benchmark" / "cases" / cid).iterdir()):
            if f.is_file() and f.suffix != ".pyc":
                h.update(f"{cid}/{f.name}".encode())
                h.update(f.read_bytes())
    for name in ("variant_vulnerable_lines.jsonl", "variant_vulnerable_lines_v2_additions.jsonl"):
        h.update((ROOT / "benchmark" / name).read_bytes())
    return h.hexdigest()


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, cwd=str(ROOT)).stdout.strip()


def prompt_fingerprints():
    sys.path.insert(0, str(ROOT / "pipeline" / "tests"))
    import inspect
    import verify_prompt_hashes as V
    return {name: (hashlib.sha256(inspect.getsource(getattr(LLMClient, name)).encode()).hexdigest(), expected)
            for name, expected in V.PINNED.items()}


# ---------------------------------------------------------------- model clients
class FakeAPI:
    """Dry-run only: deterministic replies, no inference. First a reply that is not a rule, then a rule that parses and
    runs but also flags the patched file, so every attempt of every workflow is exercised."""
    def __init__(self):
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))
        self.n = 0

    def create(self, model, messages, **kw):
        self.n += 1
        user = messages[-1]["content"]
        lang = (re.search(r"in (python|java|javascript|typescript) code", user) or [None, "python"])[1]
        if self.n % 2 == 1:
            text = "this is not a rule"
        elif "JSON" in messages[0]["content"]:
            text = json.dumps({"id": "dryrun-rule", "message": "dry run", "severity": "ERROR", "languages": [lang],
                               "pattern": "$F(...)"})
        else:
            text = ("rules:\n- id: dryrun-rule\n  languages: [%s]\n  message: dry run\n  severity: ERROR\n"
                    "  pattern: $F(...)\n" % lang)
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
                               usage=SimpleNamespace(prompt_tokens=len(user) // 4, completion_tokens=len(text) // 4))


def build_client(entry, mode, temperature=0.0, cell=None):
    provider = entry["provider"]
    if mode == "dryrun":
        key, base = "dryrun-no-key", "http://dryrun.invalid/v1"
    elif provider == "gptlab":
        key, base = get_key_for_host(entry["host"]), host_base_url(entry["host"])
    elif provider == "openai":
        key, base = get_key_for_host("OPENAI"), host_base_url("OPENAI")
    else:
        raise NotImplementedError(f"provider {provider!r}: add an adapter once the commercial models are decided "
                                  "(specification 4a: reasoning models need their own effort and output settings)")
    cfg = Config(max_files_changed=1, max_retries=3, openrouter_api_key=key, openrouter_base_url=base,
                 model_name=entry["tag"], generation_temperature=temperature, max_output_tokens=2048)
    S.apply_part2_cell(cfg, cell) if cell else S.apply(cfg)
    client = LLMClient(cfg)
    if mode == "dryrun":
        client.client = FakeAPI()
    return client


# ---------------------------------------------------------------- freeze checks and manifest
def freeze_checks(cases, models_cfg, mode):
    problems = []
    try:
        SR.assert_pinned_version()
    except Exception as e:  # noqa: BLE001 -- reported, not raised: the caller decides by mode
        problems.append(f"semgrep: {e}")
    for name, (got, expected) in prompt_fingerprints().items():
        if got != expected:
            problems.append(f"prompt fingerprint changed: {name}")
    for cid, f, status, msg in TP.preflight(cases):
        problems.append(f"sample does not parse: {cid}/{f} ({status})")
    for cid, st in missing_ranges(cases):
        problems.append(f"no bug lines: {cid} {st}")
    if mode != "dryrun":
        if str(models_cfg.get("status", "")).upper().startswith("DRAFT"):
            problems.append("models file is still a DRAFT")
        if git("status", "--porcelain", "--untracked-files=no"):
            problems.append("tracked files have uncommitted changes")
        if FREEZE_TAG not in git("tag", "--points-at", "HEAD").split():
            problems.append(f"HEAD is not tagged {FREEZE_TAG}")
        providers = {m["provider"] for m in models_cfg["part1_models"] + models_cfg.get("commercial_models", [])}
        if "gptlab" in providers and not os.environ.get("GPTLAB_API_KEY"):
            problems.append("GPTLAB_API_KEY is not set")
        if "openai" in providers and not os.environ.get("OPENAI_API_KEY"):
            problems.append("OPENAI_API_KEY is not set")
    return problems


def make_manifest(mode, cases, part2_cases, models_cfg, models_file, problems):
    return {"mode": mode, "created_at": now(), "git_commit": git("rev-parse", "HEAD"),
            "git_tags_at_head": git("tag", "--points-at", "HEAD").split(),
            "semgrep_version": SR.semgrep_version(),
            "prompt_fingerprints": {k: v[0] for k, v in prompt_fingerprints().items()},
            "models_file_sha256": sha256_file(models_file), "models": models_cfg,
            "benchmark_sha256": benchmark_sha256(cases), "cases": cases, "case_order": S.run_order(cases),
            "part2_cases": part2_cases,
            "settings": {"rule_schema_policy": S.RULE_SCHEMA_POLICY, "prompt_variant": S.PROMPT_VARIANT,
                         "max_attempts": E.MAX_ATTEMPTS, "autogrep_max_attempts": E.AUTOGREP_MAX_ATTEMPTS,
                         "iterative_budget": [E.ITERATIVE_MAX_LLM_CALLS, E.ITERATIVE_MAX_INPUT_TOKENS,
                                              E.ITERATIVE_MAX_OUTPUT_TOKENS, E.ITERATIVE_MAX_WALL_CLOCK_SECONDS],
                         "part2_cells": S.PART2_CELLS, "part2_max_attempts": S.PART2_MAX_ATTEMPTS,
                         "case_order_seed": S.CASE_ORDER_SEED},
            "freeze_problems_at_start": problems}


RESUME_KEYS = ("mode", "git_commit", "models_file_sha256", "benchmark_sha256", "cases", "part2_cases",
               "prompt_fingerprints", "semgrep_version")


# ---------------------------------------------------------------- execution
class Runner:
    def __init__(self, run_dir, mode, models_cfg, cases, part2_cases, reps_override=None, log=print):
        self.dir, self.mode, self.cfg, self.cases, self.part2_cases = Path(run_dir), mode, models_cfg, cases, part2_cases
        self.order = S.run_order(cases)
        self.part2_order = [c for c in self.order if c in set(part2_cases)]
        self.stability_reps = reps_override or models_cfg["stability"]["repeats"]
        self.part2_reps = reps_override or models_cfg["part2"]["repeats"]
        self.log_fn = log
        self.stop = threading.Event()
        self.locks = {}
        self.host_slots = {}
        self.file_lock = threading.Lock()
        self.missing = 0

    def log(self, msg):
        line = f"{now()} {msg}"
        with self.file_lock:
            with open(self.dir / "progress.log", "a") as f:
                f.write(line + "\n")
        self.log_fn(line)

    def _slot(self, entry):
        host = entry.get("host", entry["provider"])
        with self.file_lock:
            if host not in self.host_slots:
                self.host_slots[host] = threading.Semaphore(self.cfg.get("max_concurrent_per_host", 1))
            return self.host_slots[host]

    @staticmethod
    def done(path):
        return {json.loads(l)["case_id"] for l in Path(path).read_text().splitlines() if l.strip()} if Path(path).exists() else set()

    def append(self, path, record):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(record) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def episode(self, out_path, entry, cid, phase, temperature=0.0, cell=None, rep=None, _meta=None, **kw):
        """Run one episode and append it to out_path. kw goes to run_episode; _meta is runner bookkeeping
        (Part II C/D: whether the case has a probe), stored on the record."""
        if self.stop.is_set():
            return
        client = build_client(entry, self.mode, temperature, cell)
        pi = load_case(cid, client.config)
        language = pi.file_changes[0].language
        with self._slot(entry):
            try:
                ep = E.run_episode(client, pi, ROOT / "benchmark" / "cases" / cid, language, load_location_ranges(cid),
                                   self.dir.name, cid, entry["tag"], **kw)
            except E.InfraError as e:
                with self.file_lock:
                    self.missing += 1
                self.append(self.dir / "infra_failures.jsonl",
                            {"at": now(), "phase": phase, "model": entry["tag"], "case_id": cid, "cell": cell,
                             "rep": rep, "error": str(e)})
                self.log(f"INFRA {phase} {entry['tag']} {cid} {cell or ''} {rep or ''}: {e}")
                return
        rec = ep.to_dict()
        if _meta and "probe_eligible" in _meta:
            rec["probe_eligible"] = _meta["probe_eligible"]
        rec.update({"phase": phase, "cell": cell, "rep": rep, "temperature": temperature, "finished_at": now()})
        self.append(out_path, rec)

    def _parallel(self, jobs):
        """jobs: {model_tag: callable}. Runs them in parallel; the first non-infrastructure error stops everything."""
        errors = []
        def guard(fn):
            try:
                fn()
            except BaseException as e:      # a real bug: stop every worker, then re-raise (stop rule 3)
                self.stop.set()
                errors.append(e)
        with ThreadPoolExecutor(max_workers=max(1, len(jobs))) as ex:
            list(ex.map(guard, jobs.values()))
        if errors:
            raise errors[0]

    def part1(self):
        def worker(entry):
            path = self.dir / "part1" / model_key(entry["tag"]) / "episodes.jsonl"
            have = self.done(path)
            for cid in self.order:
                if cid not in have:
                    self.episode(path, entry, cid, "part1")
            self.log(f"part1 {entry['tag']} done")
        models = self.cfg["part1_models"] + self.cfg.get("commercial_models", [])
        self._parallel({m["tag"]: (lambda m=m: worker(m)) for m in models})

    def stability(self):
        temp = self.cfg["stability"]["temperature"]
        def worker(entry):
            for rep in range(1, self.stability_reps + 1):
                path = self.dir / "stability" / f"rep{rep}" / model_key(entry["tag"]) / "episodes.jsonl"
                have = self.done(path)
                for cid in self.order:
                    if cid not in have:
                        self.episode(path, entry, cid, "stability", temperature=temp, rep=rep, max_attempts=1,
                                     use_iterative_budget=False, workflows=("single_shot",))
            self.log(f"stability {entry['tag']} done")
        models = self.cfg["part1_models"] + self.cfg.get("commercial_models", [])
        self._parallel({m["tag"]: (lambda m=m: worker(m)) for m in models})

    def part2(self):
        probe_dir = self.dir / "part2" / "_probes"
        probes = {}
        for cid in self.part2_order:
            folder = probe_dir / cid
            if folder.exists():
                ext = next(folder.iterdir()).suffix
                probes[cid] = (folder / f"vulnerable_probe{ext}", folder / f"patched_probe{ext}")
            else:
                paths, rec = P.materialize(cid, probe_dir)
                probes[cid] = paths
                self.append(probe_dir.parent / "probes.jsonl", rec)

        def worker(entry):
            key = model_key(entry["tag"])
            for cid in self.part2_order:
                for rep in range(1, self.part2_reps + 1):
                    for cell, spec in S.PART2_CELLS.items():
                        path = self.dir / "part2" / cell / f"rep{rep}" / key / "episodes.jsonl"
                        if cid in self.done(path):
                            continue
                        files = probes[cid] if spec["probe"] else None
                        meta = {"probe_eligible": (files is not None)} if spec["probe"] else {}
                        self.episode(path, entry, cid, "part2", cell=cell, rep=rep, max_attempts=S.PART2_MAX_ATTEMPTS,
                                     use_iterative_budget=False, probe_files=files, workflows=("single_shot", "autogrep"),
                                     _meta=meta)
            self.log(f"part2 {entry['tag']} done")
        self._parallel({m["tag"]: (lambda m=m: worker(m)) for m in self.cfg["part2_models"]})


# ---------------------------------------------------------------- command line
def main(argv=None, log=print):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--mode", required=True, choices=sorted(MODE_DIRS))
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--models-file", default=str(MODELS_FILE))
    ap.add_argument("--parts", default="part1,stability,part2")
    ap.add_argument("--cases", type=int, help="smoke/dryrun only: number of cases (first ones in the seeded order)")
    ap.add_argument("--reps", type=int, help="smoke/dryrun only: repeats for stability and Part II")
    a = ap.parse_args(argv)

    run_dir = Path(a.run_dir).resolve()
    expected_root = (ROOT / MODE_DIRS[a.mode]).resolve()
    if expected_root not in run_dir.parents:
        raise SystemExit(f"--mode {a.mode} runs must live under {MODE_DIRS[a.mode]}/ (got {a.run_dir})")
    if a.mode == "real" and (a.cases or a.reps):
        raise SystemExit("--cases/--reps are for smoke and dry runs only")

    models_cfg = json.loads(Path(a.models_file).read_text())
    cases = S.eligible_cases()
    if a.cases:
        cases = sorted(S.run_order(cases)[: a.cases])
    p2 = models_cfg["part2"]["cases"]
    part2_cases = S.part2_cases(None if p2 == "all" else int(p2), cases=cases)
    reps = a.reps or (1 if a.mode in ("smoke", "dryrun") else None)

    problems = freeze_checks(cases, models_cfg, a.mode)
    for p in problems:
        log(f"FREEZE CHECK: {p}")
    if a.mode == "real" and problems:
        raise SystemExit(f"refusing to start the real run: {len(problems)} freeze check(s) failed")

    run_dir.mkdir(parents=True, exist_ok=True)
    manifest = make_manifest(a.mode, cases, part2_cases, models_cfg, a.models_file, problems)
    mpath = run_dir / "manifest.json"
    if mpath.exists():
        old = json.loads(mpath.read_text())
        changed = [k for k in RESUME_KEYS if old.get(k) != manifest.get(k)]
        if changed:
            raise SystemExit(f"cannot resume {run_dir}: {', '.join(changed)} changed since it started -- "
                             "start a new run directory")
        log(f"resuming {run_dir.name}")
    else:
        mpath.write_text(json.dumps(manifest, indent=1))

    runner = Runner(run_dir, a.mode, models_cfg, cases, part2_cases, reps_override=reps, log=log)
    for part in a.parts.split(","):
        runner.log(f"phase {part} started")
        getattr(runner, part)()
        runner.log(f"phase {part} finished")
    status = "complete" if runner.missing == 0 else f"{runner.missing} episode(s) missing after API failures: run again to resume"
    runner.log(f"run {status}")
    return 0 if runner.missing == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
