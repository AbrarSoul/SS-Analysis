# C/D development pilot commands

**Live execution started:** Credential setup succeeded. The authorized pilot is running; see `Execution_Status.json` and the command journal for current status. Prior missing-key notices below are historical.

Authorized by the user on 2026-10-14: 12 runs, 288 episodes, at most 864 model calls. First launch is blocked before any model call because GPTLAB_API_KEY is missing from the execution environment. See Execution_Status.json. All run destinations remain unused; approval persists once the credential is available.

Run from `/Users/nkabmo/Desktop/Tools/SS`, with the relevant provider credential available in your terminal. Never paste credentials into logs or chat.

Execute one command at a time in the listed order (three C/D and three D/C blocks). Do not overwrite any output directory.

After each run, verify exit=0; summary requested/completed=24; environment model/condition/construction mode and manifest hash; probe eligible/ineligible=11/13; generation_calls<=72 and each episode<=3 attempts. Reconcile actual raw requests, errors and usage with episode resource records. An exhausted or scan-error episode remains a measured failure, not a reason to rerun it.

Pause on process/integrity/credential/infrastructure failure. Preserve partial raw calls, outputs and consumed budget; do not restart a used namespace or silently reset attempts. Diagnose and record recovery before proceeding. No automatic resume is implemented. Do not stop early merely because scores look good or bad.

Final analysis: report all 24 cases, per model, averaging each case across its three repeats; compare C-A and D-B. Show eligible-subset results separately, probe repairs/failures, hidden TPs/FPs with scan-success denominators, scan errors and actual resources. These are descriptive development results, not confirmation evidence.

Comparability: inputs and first-call prompts verified against A/B; C/D uses fixed case order and a later execution batch. See allocation.json and verification.json.

## 1. qwen3-coder:30b / repeat 1 / condition C

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_qwen3_r1_c -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --condition C --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_qwen3_r1_c
```

## 2. qwen3-coder:30b / repeat 1 / condition D

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_qwen3_r1_d -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --condition D --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_qwen3_r1_d
```

## 3. gpt-4o / repeat 1 / condition D

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_gpt4o_r1_d -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --condition D --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_gpt4o_r1_d
```

## 4. gpt-4o / repeat 1 / condition C

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_gpt4o_r1_c -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --condition C --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_gpt4o_r1_c
```

## 5. gpt-4o / repeat 2 / condition C

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_gpt4o_r2_c -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --condition C --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_gpt4o_r2_c
```

## 6. gpt-4o / repeat 2 / condition D

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_gpt4o_r2_d -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --condition D --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_gpt4o_r2_d
```

## 7. qwen3-coder:30b / repeat 2 / condition D

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_qwen3_r2_d -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --condition D --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_qwen3_r2_d
```

## 8. qwen3-coder:30b / repeat 2 / condition C

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_qwen3_r2_c -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --condition C --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_qwen3_r2_c
```

## 9. qwen3-coder:30b / repeat 3 / condition C

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_qwen3_r3_c -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --condition C --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_qwen3_r3_c
```

## 10. qwen3-coder:30b / repeat 3 / condition D

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_qwen3_r3_d -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --condition D --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_qwen3_r3_d
```

## 11. gpt-4o / repeat 3 / condition D

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_gpt4o_r3_d -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --condition D --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_gpt4o_r3_d
```

## 12. gpt-4o / repeat 3 / condition C

```sh
.venv/bin/python pipeline/diagnostic_audit.py run cd_dev_20261014_v1_gpt4o_r3_c -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --condition C --selection benchmark/diagnostic_20261010/selection.json --probe-manifest benchmark/diagnostic_20261010/dev_probe_manifest_v1.json --output results/diagnostic_20261010/cd_dev_20261014_v1_gpt4o_r3_c
```
