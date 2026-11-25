# Ground-truth review

Independent check of every benchmark case's labels (checks A–J), done by two or more reviewers. The rules are in the project's `CLAUDE.md`, and the per-case procedure is in `.claude/skills/review-case/SKILL.md`.

| Path | What it is |
|---|---|
| `record_template.md` | Review record, one per case per reviewer. `agreement.py` reads its front matter. |
| `auto_checks.py`, `auto_checks/` | Stage 1: automatic checks on every case (hashes, GitHub match, compile errors, stubs, label leaks, `vulnerable_lines` vs patch). Read-only. |
| `agreement.py` | Compares two reviewers' records: agreement and Cohen's kappa per check, plus a list of disagreements. |
| `webapp/` | The review site judges use (Fly.io). See `webapp/DEPLOY.md`. |
| `harness_runner/` | Runs a case's attack harness against all six samples in network-less containers. Contract: `harness_runner/CONTRACT.md`; worked pilot: `harness_runner/pilot/CASE-0075/`. |
| `examples/records/R1/CASE-0075.md` | A finished record (shown to judges as the worked example). |
| `examples/changelog.json` | Format for recording corrections to the benchmark. |
| `cases_reviewed_<reviewer>/` | Each reviewer's records, harnesses and `progress.csv`. Git-ignored until the review is complete. |

Stage 1 (see `CLAUDE.md` for the environment it needs):

```
python3 review/auto_checks.py --cases benchmark/cases --out review/auto_checks \
    --reference benchmark/all_cases_reference.csv --only-status eligible,excluded --fetch
```
