# Phase 5 VM Runbook

Every command actually used to verify, prepare, and launch the Phase 5 primary benchmark on the CSC VM (`semvm`), in the order they were run. Written up 2026-09-29 after the run was launched (see `Implementation_Log.md` Sections 12.26–12.28 for the reasoning and the findings each stage surfaced). Kept as a reference for re-running this same process later — e.g. launching the Section 13.4 stability experiment, or setting up a second VM.

All commands run from the user's own Mac terminal unless noted "on the VM" — Claude proposes commands, the user runs them (standing access-control preference, see `csc_access_preference.md` memory).

`semvm` is an SSH alias already configured in `~/.ssh/config`:
```
Host semvm
    HostName 86.50.20.198
    User ubuntu
    IdentityFile ~/.ssh/sem-ssh.pem
```

---

## Stage 1 — Confirm the VM is reachable

```bash
ssh semvm "hostname && uptime && df -h ~ && python3 --version"
```
Check: hostname resolves, load is reasonable, and there's several GB free (the full transfer is ~50MB, so almost any free space is enough).

## Stage 2 — Transfer only what generation actually needs

Run from `~/Desktop/Tools/SS` on the Mac. This is NOT the full 129GB project — only the files `pipeline/case_loader.py` and `pipeline/run_generation.py` actually read at runtime: pipeline code, Autogrep's source + its `rules/` directory (not its local clone cache or old `generated_rules/` output — both stale local artifacts), and the curated dataset. `torch`/`sentence-transformers` are deliberately excluded — confirmed `autogrep/main.py` never imports `rule_filter.py`, so they're a dataset-curation-only dependency, not needed for generation.

```bash
cd ~/Desktop/Tools/SS
rsync -avz --relative \
  pipeline \
  Complete_Experimental_Design_LLM_Semgrep_MultiAgent.md \
  autogrep/*.py autogrep/PINNED_COMMIT autogrep/PINNED_VERSIONS.txt autogrep/rules \
  benchmark/cases benchmark/model_context benchmark/cwe_definitions.json \
  benchmark/manifest_frozen.jsonl benchmark/manifest_frozen_final.jsonl \
  benchmark/freeze_record.json benchmark/freeze_record_final.json \
  semvm:~/SS/
```
Result when this was run: 48MB landed on the VM.

## Stage 3 — Set up the Python environment on the VM

```bash
ssh semvm "cd ~/SS && python3 -m venv .venv && .venv/bin/pip install semgrep==1.177.0 openai==3.13.0 GitPython==3.1.62 PyYAML==6.0.3 requests==2.34.2 && .venv/bin/semgrep --version"
```
Check: the last line must print `1.177.0` — the exact pinned Semgrep version (`PINNED_CONFIG.md`), not whatever the system's own `semgrep` happens to be.

## Stage 4 — Verify the pipeline reproduces identical behaviour, before any key or GPT-Lab traffic

`pipeline/tests/run_fake_llm_final.py` and `pipeline/tests/gold_rules_final/` also need to be on the VM for this (they're small, included by the Stage 2 `pipeline` sync since they live under `pipeline/tests/`).

```bash
ssh semvm "cd ~/SS && PATH=.venv/bin:\$PATH .venv/bin/python pipeline/tests/run_fake_llm_final.py /tmp/vm_smoke"
```
Check: output must match the local run exactly — 3 of 5 canned test cases succeed with the same rule ids, 2 fail in the same documented way, zero `Cloning repository`/`Found commit` lines (curated-case validation is clone-free, see Section 12.24).

## Stage 5 — Sync any code/data fixes found while preparing the launch

Two fixes were found and made *after* Stage 4 passed, while drafting the exact launch command — both needed to reach the VM before launching:

```bash
# --cases final was added (fixing a dormant --cases pilot bug, Section 12.27)
rsync -avz pipeline/run_generation.py semvm:~/SS/pipeline/run_generation.py

# the Section 13.4 stability-experiment subset, frozen before any primary-run results exist
rsync -avz benchmark/stability_subset_100.json semvm:~/SS/benchmark/stability_subset_100.json
```

If re-running this whole process later, just fold these two paths into the Stage 2 rsync file list instead of syncing them separately.

## Stage 6 — Launch, inside tmux

**6a. On the VM, start a detachable session:**
```bash
ssh semvm
tmux new -s phase5
```

**6b. Inside tmux, load the key without it ever appearing in a command line (so it never lands in shell history):**
```bash
read -s -p "GPT-Lab API key: " GPTLAB_API_KEY
export GPTLAB_API_KEY
```
Type/paste the key at the prompt (hidden, nothing echoes), press Enter, then run the `export` line separately.

Verify it's actually loaded (length only, never the value):
```bash
echo ${#GPTLAB_API_KEY}
```

**6c. Go to the project directory:**
```bash
cd ~/SS
```

**6d. Launch the primary run:**
```bash
PATH=.venv/bin:$PATH .venv/bin/python pipeline/run_generation.py --models primary --cases final --prompt-variant autogrep_default --results-dir results/runs_phase5_primary 2>&1 | tee results/phase5_primary.log
```
Known cosmetic issue: `tee` will fail silently if `results/` doesn't exist yet on the VM (it can't create the parent directory) — the actual run is unaffected either way, since Python creates `results/runs_phase5_primary/` itself internally. Run `mkdir -p results` first to avoid losing the on-screen mirror to a log file.

**6e. Confirm it's genuinely running** (don't detach until this shows real progress):
```bash
ssh semvm "for d in ~/SS/results/runs_phase5_primary/*__autogrep_default/; do echo \$d \$(wc -l < \$d/generation_log.jsonl); done"
```
Each completed case writes 2 lines (a raw record + an autogrep record) per model's `generation_log.jsonl`. Only the models on the front of each GPU host's list will show a directory at first — each host (`GPU-farmi-001`/`-003`/`-004`) processes its own models sequentially while the three hosts run concurrently; that's expected, not a problem.

**6f. Detach**: hold `Ctrl`, press `b`, release both, then press `d`. The job keeps running on the VM independent of the SSH connection.

## Stage 7 — Check on it later, any time

```bash
# quick progress check (completed cases per model, out of 300; divide the number shown by 2)
ssh semvm "for d in ~/SS/results/runs_phase5_primary/*__autogrep_default/; do echo \$d \$(wc -l < \$d/generation_log.jsonl); done"

# reattach for a live view
ssh semvm "tmux attach -t phase5"
# (Ctrl-b d to detach again without stopping it)

# last lines without attaching, if results/phase5_primary.log exists
ssh semvm "tail -30 ~/SS/results/phase5_primary.log"
```

**Resume behaviour**: if the run is ever interrupted, re-running the exact same Stage 6d command resumes rather than restarts — `_completed_case_ids()` skips any case+model combination that already has both a `raw` and an `autogrep` result logged, so nothing already done gets redone or re-billed.

---

## Stage 8 — Phase 7 analysis, once results are pulled locally

Pull the primary run's result logs back to the Mac (not the raw captures/generated-rules/repo-cache directories, which stay on the VM):
```bash
cd ~/Desktop/Tools/SS
mkdir -p results
rsync -avz --exclude 'shared_cache' --exclude 'cache' --exclude 'raw' --exclude 'raw_retries' \
  --exclude 'synthetic_patch_names' --exclude 'generated_rules' \
  semvm:~/SS/results/runs_phase5_primary/ results/runs_phase5_primary/
```

Run the analysis (Section 21 metrics, Section 7.3 representability split, Section 12.23 precision-outlier handling):
```bash
.venv/bin/python pipeline/analyze_phase5_primary.py
```
See `Implementation_Log.md` Section 12.31 for what it computes and two real bugs found while building/running it (both fixed before trusting any output).

## Stage 9 — Section 13.4 stability experiment (after the primary run)

The 100-case subset was frozen BEFORE the primary run's results existed (`benchmark/stability_subset_100.json`, `pipeline/select_stability_subset.py`) — deliberately, to avoid any appearance of picking a convenient subset after seeing results.

**9a. Sync any fixes made since the primary launch** (`--cases stability` support, and the `reconstruct_attempt_trail()` clone-free fix from Section 12.30 — both bundled into one `run_generation.py` sync; the launch script too, if this is a fresh setup):
```bash
rsync -avz pipeline/run_generation.py semvm:~/SS/pipeline/run_generation.py
rsync -avz pipeline/run_stability_experiment.sh semvm:~/SS/pipeline/run_stability_experiment.sh
ssh semvm "chmod +x ~/SS/pipeline/run_stability_experiment.sh"
```

**9b. Verify with a tiny live test before committing to the full run** — one case, one model, real API call, through the *existing* tmux session so the already-loaded key is reused (a fresh `ssh semvm "..."` call does NOT inherit an interactive tmux session's exported variables):
```bash
ssh semvm "tmux send-keys -t phase5 'PATH=.venv/bin:\$PATH .venv/bin/python pipeline/run_generation.py --models qwen2.5-coder:7b-instruct --cases CASE-0041 --temperature 0.2 --prompt-variant autogrep_default --results-dir /tmp/stability_test' Enter"
# wait ~45s, then:
ssh semvm "cat /tmp/stability_test/*/generation_log.jsonl"
# check: temperature shows 0.2, and (if a failure) attempt_trail shows a REAL reason, not
# "repo not available for validation" -- confirms the Section 12.30 fix actually landed.
ssh semvm "rm -rf /tmp/stability_test"
```

**9c. Launch the real thing**, inside the same tmux session (key already loaded there):
```bash
ssh semvm
tmux attach -t phase5
bash pipeline/run_stability_experiment.sh
```
Runs all 5 repeats sequentially (not concurrently -- untested whether GPT-Lab tolerates 5x parallel load), each into its own `results/runs_phase5_stability_repN/` directory, each independently resume-safe. Rough estimate ~32h (~1.3 days), scaled from the primary run's actual observed timing (1.67x its total workload). Detach once repeat 1 shows real log output (`Ctrl-b` then `d`).

**9d. Check progress later**, any time:
```bash
ssh semvm "for REP in 1 2 3 4 5; do echo \"-- rep \$REP --\"; for d in ~/SS/results/runs_phase5_stability_rep\$REP/*__autogrep_default/; do echo \$d \$(wc -l < \$d/generation_log.jsonl 2>/dev/null); done; done"
```

## Stage 10 — C2 primary run (pipeline/run_c2.py)

Launched 2026-10-01 ~15:13 UTC, same `phase5` tmux session, same key already loaded there. Launch command used:
```bash
cd ~/SS && mkdir -p results && PATH=.venv/bin:$PATH .venv/bin/python pipeline/run_c2.py --models primary --cases supported --results-dir results/runs_c2_primary 2>&1 | tee results/c2_primary.log
```
153 supported final-set cases (NOT the pilot's 40 -- `--cases supported` reads `manifest_frozen_final.jsonl` directly, see Implementation_Log.md Section 12.37 for a real bug this exact point caused on the first launch attempt), all 8 primary models, temperature 0 (the default; Section 20 specifies no temperature for C2 itself).

**Check progress, any time:**
```bash
ssh semvm "for d in ~/SS/results/runs_c2_primary/*__c2/; do echo \$d \$(wc -l < \$d/c2_episode_log.jsonl 2>/dev/null)/153; done"
# reattach for a live view:
ssh semvm "tmux attach -t phase5"   # Ctrl-b d to detach again
# tail without attaching:
ssh semvm "tail -30 ~/SS/results/c2_primary.log"
```
Each completed case writes exactly 1 line to `c2_episode_log.jsonl` (unlike Phase 5's 2-lines-per-case raw+autogrep pattern) -- the line count IS the completed-case count, out of 153 per model. Resume-safe: re-running the same launch command skips any case_id already present in that model's `c2_episode_log.jsonl`.

No ETA established yet (first run of this kind) -- ballpark against Phase 5's primary run (~19h for 300 cases, up to 3 attempts each) by noting C2 allows up to 4 calls/case on roughly half as many cases (153).

## Stage 11 — Mid-run transfer from local Mac to VM (C4-A, 2026-10-05)

A run started locally on the Mac (not the VM) can be moved to the VM mid-flight without losing
progress, using the same resume-safety every runner in this project already has: stop the local
process, sync the code + the partial results to the VM, relaunch the identical command there.

```bash
# 1. Stop the local process cleanly (confirm the episode log's line count first, for reference)
pkill -f "run_c4.py --variant C4-A"

# 2. Sync the runner code (and anything it imports that might differ -- diff-checked first here,
#    all identical, so only the two just-edited files needed syncing)
rsync -avz pipeline/run_c3.py pipeline/run_c4.py semvm:~/SS/pipeline/

# 3. Sync the ALREADY-COMPLETED partial results to the matching path on the VM
ssh semvm "mkdir -p ~/SS/results/runs_c4/C4-A"
rsync -avz results/runs_c4/C4-A/c4_episode_log.jsonl results/runs_c4/C4-A/sample_execution_log.jsonl \
  semvm:~/SS/results/runs_c4/C4-A/

# 4. Launch the IDENTICAL command on the VM, inside the existing tmux session (key already loaded)
ssh semvm "tmux send-keys -t phase5 'cd ~/SS && PATH=.venv/bin:\$PATH .venv/bin/python pipeline/run_c4.py --variant C4-A --cases supported --results-dir results/runs_c4 2>&1 | tee results/c4_a_run.log' Enter"
```

Confirmed live: the VM run's own resume logic correctly reported "resuming: 64/153 already done"
(matching the local run's state at the moment it was stopped) and continued with the remaining 89,
with no case redone and no case lost. Worth checking dependency files for drift before doing this
(`diff <(cat local_file) <(ssh semvm "cat remote_file")` per file) rather than assuming everything
already on the VM is current -- in this case all 6 checked dependencies were identical, so only the
2 just-edited files needed syncing.

## What NOT to repeat

- Don't hardcode the key anywhere, on the VM or the Mac (`Open Models/models.py` reads `GPTLAB_API_KEY` from the environment; a separate, older copy of that file outside this project still has a hardcoded key and should be rotated/cleaned up independently).
- Don't paste the raw key into a plain `export KEY='...'` line — it gets written to `~/.bash_history` in plain text. Always use the `read -s -p ...` prompt from Stage 6b.
- Don't run the launch command outside `tmux` (or `screen`) — an SSH disconnect would kill a multi-day job.
