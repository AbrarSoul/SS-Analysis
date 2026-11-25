# Dataset reference guide — every case, every number, how to verify any of it yourself

Written so you can read through the dataset on your own, independent of anything Claude has
computed, and check any case against its real-world source. Two companion files:

- **`benchmark/all_cases_reference.csv`** — all 300 cases, one row each, with every field needed to
  look the case up for real (repository, the two real commit hashes, ready-to-click GitHub URLs,
  the CVE ID, an NVD lookup URL) plus which group(s) each case belongs to.
- This file — explains what every group and number actually means, which case IDs are in each one,
  and why, so the CSV's `status` column makes sense.

---

## Part 1 — Every number, in order, with the real case IDs behind it

### 40 — the pilot batch (`CASE-0001`–`CASE-0040`)

**Not part of the 300/299-case dataset at all.** Confirmed directly: the frozen manifest
(`benchmark/manifest_frozen_final.jsonl`) starts at `CASE-0041` and has exactly 300 rows — the
40 pilot cases are a separate, earlier batch, built first to pilot-test the curation process and
screen candidate models (`results/runs_pilot_screening/`), before the main 300-case dataset was
built. They don't appear in `all_cases_reference.csv` and don't affect any number below. Mentioned
here only so you don't go looking for them in the 300 and wonder where they went.

### 300 — the full built dataset (`CASE-0041`–`CASE-0342`, with 2 gaps)

Every case that was actually curated and given a complete 6-sample bundle (vulnerable source,
patched source, two reworded vulnerable variants, one alternative fix, one benign look-alike).
Confirmed: 300 rows in `manifest_frozen_final.jsonl`, IDs running from `CASE-0041` to `CASE-0342`
(not contiguous — a small number of IDs in that range were never used, from early exclude-and-replace
cycles during curation).

### 299 — after one case was dropped for an unrelated defect

**`CASE-0166`** was excluded after the fact: its "patched" (supposedly fixed) source file doesn't
even compile — a defect in the upstream repository's own commit, unrelated to anything about the
vulnerability itself. `300 - 1 = 299`. **This is the number the paper's abstract calls the benchmark
size.** It still physically exists in `manifest_frozen_final.jsonl` (300 raw rows) but is filtered
out by `pipeline/eligible_cases.py`'s `load_manifest()`, which every analysis script uses instead of
reading the raw file directly.

### 153 — the "supported" bucket, before further cuts

Every one of the 299 cases was classified into exactly one of three buckets, based on whether the
*kind* of vulnerability is even expressible as a Semgrep pattern rule at all:

| Bucket | Count | Meaning |
|---|---|---|
| `supported` | 153 | The vulnerable code has a matchable shape (dangerous call, missing check, incomplete deny-list, local data flow) |
| `partially_supported` | 99 | Part of the mechanism depends on context outside the function being matched |
| `unsupported` | 47 | The vulnerability can't be localized this way at all (e.g. timing side-channels, cross-component authorization logic) |

`153 + 99 + 47 = 299`, confirmed. This classification was done by one person following a written
rubric during curation, then checked by a second person on a blind 45-case sample (77.8% agreement,
Cohen's κ=0.66 — "substantial" but not perfect agreement; see Issue 6 in
`Supervisor_Review_20261018.md` for the full honesty about what this check does and doesn't
establish).

### 150 — the actual evaluated population, after 3 more exclusions

Of the 153 "supported" cases, 3 more were pulled out, for a reason distinct from the classification
above: on closer inspection, their real-world "fix" doesn't actually fix the vulnerability (so
treating the patched version as a verified-safe negative sample would be misleading). Confirmed
precisely, by case ID:

| Case | Why it was pulled |
|---|---|
| `CASE-0140` | Upstream deny-list is bypassable via percent-encoding (measured directly against the real library) |
| `CASE-0156` | Upstream deny-list bypassed via a relative-path scan combined with glob (measured directly) |
| `CASE-0194` | Path check uses `startsWith` without a separator — classic sibling-directory bypass (measured directly) |

`153 - 3 = 150`. **This is the number every actual result in the paper is computed on — the single
most important number if you remember only one.**

Two more cases (`CASE-0125`, `CASE-0174`) have the *same kind* of problem (upstream fix doesn't
really work) but were originally classified `partially_supported`, not `supported` — so excluding
them doesn't change the 150 count; they were never in that bucket to begin with. They're recorded
in `benchmark/ground_truth_exclusions.json` alongside the three above, for completeness, but only
the three in the table actually subtract from 153.

### 38 — not a dataset number at all; a subset Claude selected for the Phase 2 audit

**Chosen by me**, not a property of the dataset. Of the 150 eligible cases, these are the ones
where models consistently fail across the *entire study* (all 16 models, every condition) on either
the restructured hidden variant (36 cases, some with up to 44 independent failed attempts) or the
alternative-fix sample (5 cases, 3 of which overlap with the first 36 — union is 38). The logic: if
any of these cases' ground truth is actually wrong, it would currently be indistinguishable from a
genuine model limitation, which is exactly the risk Issue 2 raised. Full derivation in
`Supervisor_Review_20261018.md`'s Issue 2 section. Marked `priority-audit-38` in the CSV.

---

## Part 2 — How to verify any case against its real source yourself

Every case's manifest entry carries exactly what you need to check it independently, with no
dependency on understanding this project's internal pipeline. Confirmed directly by tracing one
case (`CASE-0041`) all the way back: its record in the raw MoreFixes-derived candidate list
(`data/morefixes_v4/candidates_with_cve_cwe.csv`) reads:

```
github.com_1Panel-dev_MaxKB_24cd68acae...patch, https://github.com/1Panel-dev/MaxKB,
24cd68acae5f726eed828e2ac801827a2a70536f, CVE-2026-39424, 1337, NVD_DIRECT_COMMIT,
CWE-1236, Improper Neutralization of Formula Elements in a CSV File
```

That `NVD_DIRECT_COMMIT` tag means NVD's own CVE record links directly to this exact commit as the
fix — i.e. the ultimate source isn't this project's own judgment, it's NVD's.

### Step-by-step verification for any case

1. **Open `benchmark/all_cases_reference.csv`** and find the row for the case ID you want to check.
2. **Click `github_vulnerable_commit_url`** — this takes you to the real commit on GitHub, exactly
   as it existed before the fix. Read the actual file at `changed_file` and compare it to
   `benchmark/cases/CASE-XXXX/vulnerable_source.*` in this repo — they should match (the case file
   is a standalone extraction of this exact commit's version of that one file).
3. **Click `github_fixed_commit_url`** — the real fix commit. Read the diff yourself; compare
   against `patched_source.*` and `patch.diff` in the case folder.
4. **Click `nvd_url`** (built from the case's CVE ID) — read NVD's own description of the
   vulnerability and compare it to the case's `cwe_ids` and the mechanism described in that case's
   build script docstring (`pipeline/section9_final/build_bundle_caseNNNN.py`, or
   `pipeline/build_bundle_caseNNNN.py` for cases below `CASE-0041`... though note, per Part 1, cases
   below `CASE-0041` are pilot cases not in the 300).
5. **Optional, offline cross-check**: search `data/morefixes_v4/candidates_with_cve_cwe.csv` (or
   `candidates_deduplicated.csv`) for the case's `fixed_commit` hash — this shows the original,
   pre-curation MoreFixes record and its source-type tag (e.g. `NVD_DIRECT_COMMIT` means NVD itself
   links the commit; other tags in that file indicate different sourcing paths — worth reading a few
   to see the range before trusting one in isolation).
6. **Check a GitHub Security Advisory directly**, if the case has a `ghsa_id` in its full
   `metadata.json` (`benchmark/cases/CASE-XXXX/metadata.json`) — not every case has one, since not
   every CVE has a corresponding GHSA entry, but when present it's another independent source to
   cross-check the same vulnerability description against.

### Caveats worth knowing before you start

- Some repositories may have been renamed, made private, or deleted since the data was collected —
  a 404 on a GitHub URL doesn't necessarily mean the case is wrong, just that you may need to search
  the CVE/GHSA ID directly instead, or check if the repo moved.
- The `vulnerable_lines` field in the manifest (and the per-case `metadata.json`) marks exactly
  which lines in the vulnerable file are considered "the vulnerable construct" for scoring purposes
  — worth checking this matches your own read of where the real vulnerability actually is, since
  this is exactly the kind of judgment call Issue 3 (location-aware scoring) depends on.
- For the hidden samples specifically (the renamed/restructured/alt-fix/benign-lookalike files, not
  covered by the CSV above since they don't come from MoreFixes at all — they're generated, not
  sourced), there is no external "real source" to check against the same way; that's exactly what
  Issue 2's audit is about, and is a separate verification task from what this guide covers.
