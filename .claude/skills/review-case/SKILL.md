---
name: review-case
description: Run the ground-truth review checklist (checks A-J) on one benchmark case and draft a review record. Use when the user asks to review, verify or audit a CASE-XXXX for the benchmark ground truth.
---

# Review one benchmark case (checks A-J)

You are assisting a human reviewer. You gather evidence, build and run tests, and
draft the record. The reviewer makes every final call. Arguments: the case id
(e.g. `CASE-0075`) and the reviewer tag (`R1` or `R2`; default `R1`).
`<reviewer>` below is the lower-case tag: R1 works in `review/cases_reviewed_r1/`
(records `<CASE>.md`, harnesses `harness/<CASE>/`, progress in `progress.csv`).

## Hard rules
- NEVER modify anything under `benchmark/`. Work only in `review/`.
- NEVER open `results/`, model outputs, or another reviewer's records
  (`review/cases_reviewed_<other reviewer>/`). Blind review is the point.
- Do not read `metadata.json`'s `vulnerable_lines` until you have written down your
  own bug location (step 4).
- Every answer must cite evidence you actually observed (a diff, a test run, a URL).
  If you could not run something, say "reasoned, not executed".
- Mark the record `status: draft` until the reviewer confirms each answer.

## Steps

1. **Load the case.** Read `benchmark/cases/<CASE>/` (all 6 samples, `patch.diff`;
   from `metadata.json` read only cve_id, cwe_ids, repository, commits,
   changed_file, language for now). Read its row in
   `benchmark/all_cases_reference.csv` and its line in
   `review/auto_checks/auto_checks.csv` (Stage 1 flags) if present. Read only the
   `flags` column now: the `notes` text for `fix_outside_lines` quotes
   `vulnerable_lines`, so leave it until after step 4.

2. **A and B - real sources.** Download `changed_file` from
   `https://raw.githubusercontent.com/<repository>/<commit>/<changed_file>` for both
   commits into `review/cases_reviewed_<reviewer>/harness/<CASE>/upstream/`. Compare byte for byte with
   `vulnerable_source.*` and `patched_source.*`; regenerate the diff and compare
   with `patch.diff`. Check SHA-256 against `artifact_hashes`.

3. **C and D - CVE record.** Look up the CVE (cve.org, an NVD mirror, the GHSA if
   `ghsa_id` is set). Record: does it reference this commit, do affected versions
   and dates fit, what CWE(s) are assigned. Save the URLs you used.

4. **F (part 1) - your own location first.** Read `vulnerable_source.*` and the
   patch. Write down every function/line range where the bug occurs. Only then read
   `vulnerable_lines` and compare. The range must cover every place the fix touches.

5. **E - does the real fix work? Run it.** In `review/cases_reviewed_<reviewer>/harness/<CASE>/`:
   - Build the smallest harness that calls the vulnerable function with attacker
     input (stub missing project classes; never pull in the whole project unless
     needed).
   - Write attack inputs: the plain exploit plus bypass attempts suited to the CWE
     (e.g. path traversal: `../`, nested `a/../../`, absolute paths, backslashes,
     sibling-prefix `../dest_evil/`, URL/percent encoding, symlinks; injection:
     quoting, encodings, alternate syntax; deny-lists: case changes, encodings,
     unlisted entries).
   - Run against vulnerable and patched. Detect success by checking the real effect
     (files outside the target ANYWHERE in the work area, command executed, etc.),
     not by log messages.
   - Expected: vulnerable exploitable, patched blocks everything, a benign input
     still works on both. If the patched version is bypassable, say so loudly - that
     is an exclusion candidate.
   - **Write the harness in contract v1** (`review/harness_runner/CONTRACT.md`):
     `harness.json` + `run.sh <sample file> <sample role>`, which prints one
     `RESULT {json}` line. Make one harness work for all six samples: find
     renamed classes or methods by pattern or reflection, not by editing each sample.
     Any repair needed just to run a sample (a missing import, an omitted body) must
     be listed in `modified`, and must never touch the bug's own logic. Template:
     `review/harness_runner/pilot/CASE-0075/`.
   - **Run it only through the runner**. It runs each sample in its own network-less
     container and writes `results.json` next to the harness:
     `python3 review/harness_runner/run_harness.py <CASE>`.
     If Docker is not running, start it with `open -a Docker`. If the image is
     missing, build it: `docker build -t gt-harness-runtime:1 review/harness_runner/runtime`.
   - Batch 1 cases: execution is expected for E, H and I. Batch 2 cases: execute where
     a harness is cheap; otherwise reason, and answer "reasoned, not executed".
   - If an attack is blocked only by an accident of the environment (for example
     Linux refusing `..` through a folder that doesn't exist), adjust the harness
     so the result reflects the code, and say so in the notes.

6. **G - representability.** Is there a local source -> sink or a matchable
   dangerous construct? If useful, write a quick Semgrep rule and run it on both
   files.

7. **H, I, J - generated samples.** Compile each (fix only in a COPY under
   `review/cases_reviewed_<reviewer>/harness/`, and record the defect). Run the same attack set:
   - both `variant_vulnerable_*` must be exploitable by the same mechanism;
   - `variant_safe_01` must block every attempt (watch for the classic flaws:
     `startsWith` without a separator, deny-lists, decode-after-check);
   - `benign_lookalike` must be safe AND contain the same kind of code; flag stubs,
     omitted bodies, and comments that reveal the label.
   - The same harness and the same `results.json` cover these checks. Cite the
     verdict line for each sample in the evidence, for example "results.json: Variant 02
     exploitable (4 attacks worked)". A sample that "did not compile" or is
     "not testable" is a finding in itself.

8. **Write the record** to `review/cases_reviewed_<reviewer>/<CASE>.md` using
   `review/record_template.md` exactly (front-matter keys A-J and `decision` are
   parsed by `agreement.py`). Add `status: draft`. Propose a decision
   (Keep / Keep with corrections / Exclude) with the exact corrections.

9. **Track progress.** Add or update the case's row in
   `review/cases_reviewed_<reviewer>/progress.csv` (case_id, date, decision, status,
   one-line summary of corrections).

10. **Report back** to the reviewer in a few lines: each check's answer, anything
   that failed or is uncertain, and what the reviewer should look at themselves
   before confirming. Do not summarise checks that passed in detail.
