## Ground-truth review rules

- During ground-truth review, never modify files under `benchmark/`. All review work goes in `review/`.
- Never open `results/` or any model output while reviewing a case. Never open another reviewer's folder (`review/cases_reviewed_<other>/`).
- Use the `review-case` skill for each case. One case per session or per `/clear`, so evidence from one case doesn't leak into the next.
- Review records follow `review/record_template.md` exactly; keep `status: draft` until the human reviewer confirms.
- Any change to a benchmark file is done only after the decision is final, in a single batch, and logged in `review/changelog.json`.
- R1 works in `review/cases_reviewed_r1/` (records `<CASE>.md`, harnesses `harness/<CASE>/`, `progress.csv`).
- Stage 1 tools: run `review/auto_checks.py` with `SSL_CERT_FILE=/etc/ssl/cert.pem` (else every GitHub fetch fails with a certificate error), `.venv/bin/python3` (has pyflakes) and `PATH="$PWD/review/.tools/node_modules/.bin:$PATH"` (local `tsc`).
- Execution harnesses follow `review/harness_runner/CONTRACT.md` (contract v1; template `review/harness_runner/pilot/CASE-0075/`). Run them only through `python3 review/harness_runner/run_harness.py <CASE>`: each sample runs in a network-less Docker container (image `gt-harness-runtime:1`, built from `review/harness_runner/runtime/`; start Docker with `open -a Docker`).
