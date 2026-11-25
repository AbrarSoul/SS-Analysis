"""
Run v2 entrypoint (pipeline/run_v2.py), exercised through real dry runs: the built-in fake model, real pinned
Semgrep, real benchmark cases, a two-model list and two cases.

What these tests establish:
- a dry run writes the results layout analyze_v2 reads, for Part I, stability and Part II (all four cells);
- running the same command again resumes: finished episodes are not redone;
- a run directory cannot be resumed after the code, benchmark, cases or models changed;
- API failures that outlast the retries are logged, leave the episode missing (exit code 2), and the next run
  fills exactly those; any other error stops the whole run;
- --mode real refuses to start while freeze checks fail, and each mode only writes under its own folder;
- the analysis reads a dry run only when explicitly allowed.
"""
import json
import shutil
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]

import analyze_v2 as A  # noqa: E402
import run_v2 as R  # noqa: E402
import run_v2_episode as E  # noqa: E402

MODELS = {
    "status": "test models file",
    "part1_models": [{"tag": "qwen2.5-coder:7b-instruct", "provider": "gptlab", "host": "GPU-farmi-001"},
                     {"tag": "codegemma:7b", "provider": "gptlab", "host": "GPU-farmi-004"}],
    "commercial_models": [],
    "part2_models": [{"tag": "qwen3-coder:30b", "provider": "gptlab", "host": "GPU-farmi-004"}],
    "stability": {"repeats": 3, "temperature": 0.2},
    "part2": {"cases": "all", "repeats": 3},
    "max_concurrent_per_host": 1,
}


@pytest.fixture()
def run_env(tmp_path, monkeypatch):
    models_file = tmp_path / "models.json"
    models_file.write_text(json.dumps(MODELS))
    run_dir = ROOT / "results_v2_dryrun" / f"pytest-{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(E, "API_BACKOFF_SECONDS", (0, 0, 0))
    yield run_dir, models_file
    shutil.rmtree(run_dir, ignore_errors=True)


def _run(run_dir, models_file, *extra, log=None):
    return R.main(["--mode", "dryrun", "--run-dir", str(run_dir), "--models-file", str(models_file), "--cases", "2",
                   *extra], log=log or (lambda m: None))


def _lines(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def test_full_dry_run_layout_and_analysis(run_env):
    run_dir, models_file = run_env
    assert _run(run_dir, models_file) == 0
    m = json.loads((run_dir / "manifest.json").read_text())
    assert m["mode"] == "dryrun" and len(m["cases"]) == 2 and m["case_order"] == R.S.run_order(m["cases"])
    for tag in ("qwen2.5-coder_7b-instruct", "codegemma_7b"):
        eps = _lines(run_dir / "part1" / tag / "episodes.jsonl")
        assert sorted(e["case_id"] for e in eps) == sorted(m["cases"])
        assert all(set(e["workflows"]) == set(E.WORKFLOWS) and e["phase"] == "part1" for e in eps)
        assert all(len(e["attempts"]) >= 3 for e in eps)                   # the fake model is never accepted
        st = _lines(run_dir / "stability" / "rep1" / tag / "episodes.jsonl")
        assert all(len(e["attempts"]) == 1 and e["temperature"] == 0.2 for e in st)
    for cell in "ABCD":
        eps = _lines(run_dir / "part2" / cell / "rep1" / "qwen3-coder_30b" / "episodes.jsonl")
        assert len(eps) == 2 and all(e["cell"] == cell and len(e["attempts"]) <= 3 for e in eps)
        assert all((e["probe_eligible"] is None) == (cell in "AB") for e in eps)       # C/D record True or False
    typed = _lines(run_dir / "part2" / "B" / "rep1" / "qwen3-coder_30b" / "episodes.jsonl")[0]["attempts"][0]
    assert "single JSON object" in typed["system_message"]
    with pytest.raises(SystemExit, match="dryrun run"):
        A.analyze(run_dir, n_boot=100)
    res = A.analyze(run_dir, n_boot=100, allow_non_real=True)
    assert {r["model"] for r in res["part1_table"].values()} == {"qwen2.5-coder_7b-instruct", "codegemma_7b"}
    assert "qwen3-coder_30b" in res["part2"]


def test_resume_does_not_redo_work(run_env):
    run_dir, models_file = run_env
    assert _run(run_dir, models_file, "--parts", "part1") == 0
    path = run_dir / "part1" / "codegemma_7b" / "episodes.jsonl"
    before = path.read_text()
    msgs = []
    assert _run(run_dir, models_file, "--parts", "part1", log=msgs.append) == 0
    assert path.read_text() == before and any("resuming" in m for m in msgs)


def test_changed_inputs_cannot_resume(run_env):
    run_dir, models_file = run_env
    assert _run(run_dir, models_file, "--parts", "part1") == 0
    m = json.loads((run_dir / "manifest.json").read_text())
    m["benchmark_sha256"] = "0" * 64
    (run_dir / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(SystemExit, match="benchmark_sha256 changed"):
        _run(run_dir, models_file, "--parts", "part1")


def test_api_failures_are_logged_and_resumed(run_env, monkeypatch):
    run_dir, models_file = run_env
    m_cases = sorted(R.S.run_order(R.S.eligible_cases())[:2])
    bad_case = m_cases[0]
    real_create = R.FakeAPI.create

    def flaky(self, model, messages, **kw):
        if self._case == bad_case:
            raise ConnectionError("server down")
        return real_create(self, model, messages, **kw)
    real_load = R.load_case

    def tagging_load(cid, config):
        tagging_load.current = cid
        return real_load(cid, config)
    monkeypatch.setattr(R, "load_case", tagging_load)
    monkeypatch.setattr(R.FakeAPI, "_case", property(lambda self: tagging_load.current), raising=False)
    monkeypatch.setattr(R.FakeAPI, "create", flaky)
    models_one = json.loads(models_file.read_text())
    models_one["part1_models"] = models_one["part1_models"][:1]
    models_file.write_text(json.dumps(models_one))

    assert _run(run_dir, models_file, "--parts", "part1") == 2
    fails = _lines(run_dir / "infra_failures.jsonl")
    assert [f["case_id"] for f in fails] == [bad_case]
    path = run_dir / "part1" / "qwen2.5-coder_7b-instruct" / "episodes.jsonl"
    assert [e["case_id"] for e in _lines(path)] == [c for c in R.S.run_order(m_cases) if c != bad_case]

    monkeypatch.setattr(R.FakeAPI, "create", real_create)              # the server is back
    assert _run(run_dir, models_file, "--parts", "part1") == 0
    assert sorted(e["case_id"] for e in _lines(path)) == m_cases


def test_a_real_bug_stops_the_run(run_env, monkeypatch):
    run_dir, models_file = run_env

    def broken(*a, **k):
        raise ValueError("a bug in the episode code")
    monkeypatch.setattr(R.E, "run_episode", broken)
    with pytest.raises(ValueError, match="a bug"):
        _run(run_dir, models_file, "--parts", "part1")


def test_real_mode_refuses_while_not_frozen(tmp_path):
    run_dir = ROOT / "results_v2" / f"pytest-{uuid.uuid4().hex[:8]}"
    msgs = []
    with pytest.raises(SystemExit, match="refusing to start the real run"):
        R.main(["--mode", "real", "--run-dir", str(run_dir)], log=msgs.append)
    assert not run_dir.exists()
    assert any("DRAFT" in m for m in msgs) and any(R.FREEZE_TAG in m for m in msgs)
    assert any("CASE-0055" in m for m in msgs)                          # the known broken files block the freeze


def test_modes_write_only_under_their_own_folder(run_env):
    _, models_file = run_env
    with pytest.raises(SystemExit, match="must live under results_v2_dryrun"):
        R.main(["--mode", "dryrun", "--run-dir", str(ROOT / "results_v2_smoke" / "x"), "--models-file", str(models_file)])
    with pytest.raises(SystemExit, match="smoke and dry runs only"):
        R.main(["--mode", "real", "--run-dir", str(ROOT / "results_v2" / "x"), "--cases", "2"])
