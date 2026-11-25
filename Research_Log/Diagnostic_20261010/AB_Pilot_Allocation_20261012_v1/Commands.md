# Proposed A/B pilot commands

Status: NOT APPROVED / NOT EXECUTED. Run from the repository root only after the live allocation is approved.

Execute sequentially in this order. Stop on any nonzero exit. Do not overwrite or restart a used namespace; preserve consumed attempts on recovery.


## 1. qwen3-coder:30b / repeat 1 / condition A

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_qwen3_r1_a -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --construction-mode original_prompt --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_1.json --output results/diagnostic_20261010/ab_dev_20261012_v1_qwen3_r1_a
```


## 2. qwen3-coder:30b / repeat 1 / condition B

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_qwen3_r1_b -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --construction-mode typed_json --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_1.json --output results/diagnostic_20261010/ab_dev_20261012_v1_qwen3_r1_b
```


## 3. gpt-4o / repeat 1 / condition B

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_gpt4o_r1_b -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --construction-mode typed_json --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_1.json --output results/diagnostic_20261010/ab_dev_20261012_v1_gpt4o_r1_b
```


## 4. gpt-4o / repeat 1 / condition A

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_gpt4o_r1_a -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --construction-mode original_prompt --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_1.json --output results/diagnostic_20261010/ab_dev_20261012_v1_gpt4o_r1_a
```


## 5. gpt-4o / repeat 2 / condition A

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_gpt4o_r2_a -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --construction-mode original_prompt --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_2.json --output results/diagnostic_20261010/ab_dev_20261012_v1_gpt4o_r2_a
```


## 6. gpt-4o / repeat 2 / condition B

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_gpt4o_r2_b -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --construction-mode typed_json --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_2.json --output results/diagnostic_20261010/ab_dev_20261012_v1_gpt4o_r2_b
```


## 7. qwen3-coder:30b / repeat 2 / condition B

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_qwen3_r2_b -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --construction-mode typed_json --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_2.json --output results/diagnostic_20261010/ab_dev_20261012_v1_qwen3_r2_b
```


## 8. qwen3-coder:30b / repeat 2 / condition A

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_qwen3_r2_a -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --construction-mode original_prompt --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_2.json --output results/diagnostic_20261010/ab_dev_20261012_v1_qwen3_r2_a
```


## 9. qwen3-coder:30b / repeat 3 / condition A

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_qwen3_r3_a -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --construction-mode original_prompt --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_3.json --output results/diagnostic_20261010/ab_dev_20261012_v1_qwen3_r3_a
```


## 10. qwen3-coder:30b / repeat 3 / condition B

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_qwen3_r3_b -- .venv/bin/python pipeline/diagnostic_v2.py model --model qwen3-coder:30b --construction-mode typed_json --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_3.json --output results/diagnostic_20261010/ab_dev_20261012_v1_qwen3_r3_b
```


## 11. gpt-4o / repeat 3 / condition B

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_gpt4o_r3_b -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --construction-mode typed_json --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_3.json --output results/diagnostic_20261010/ab_dev_20261012_v1_gpt4o_r3_b
```


## 12. gpt-4o / repeat 3 / condition A

```sh
.venv/bin/python pipeline/diagnostic_audit.py run ab_dev_20261012_v1_gpt4o_r3_a -- .venv/bin/python pipeline/diagnostic_v2.py model --model gpt-4o --construction-mode original_prompt --prompt-variant autogrep_default --acceptance-policy corrected --selection Research_Log/Diagnostic_20261010/AB_Pilot_Allocation_20261012_v1/selection_repeat_3.json --output results/diagnostic_20261010/ab_dev_20261012_v1_gpt4o_r3_a
```
