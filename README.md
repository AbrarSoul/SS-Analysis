# LLM-to-Semgrep Rule Generation: A Multi-Agent Benchmark

An evaluation of whether open-weight LLMs can convert real vulnerability-fixing patches into correct
[Semgrep](https://semgrep.dev/) static-analysis rules — tested as single models with increasing
amounts of help (one-shot generation → iterative self-repair), and as multi-agent pipelines where
different roles (patch analysis, rule generation, syntax review, semantic review, rule repair) are
played by the same or different models. Built on a fork of
[Autogrep](https://github.com/lambdasec/autogrep), evaluated against a curated, hand-verified dataset
of 299 real CVE fixes across Python, Java, JavaScript, and TypeScript, each with a 6-sample hidden
test bundle designed so a model never sees the exact data its rule will be judged against.

## Start here

**[`Research_Log/Paper_Draft_Notes.md`](Research_Log/Paper_Draft_Notes.md)** is the full results
write-up — methodology, findings, and limitations, with every section affected by the audits below
explicitly marked `[CORRECTED]`. This is the single file to read for the actual results.

## What this repository contains

| Path | Contents |
|---|---|
| `Complete_Experimental_Design_LLM_Semgrep_MultiAgent.md` | The frozen experimental design — research questions, dataset spec, metrics, written before any implementation began |
| `Research_Log/Paper_Draft_Notes.md` | **The results.** Fully corrected through two audit passes. |
| `Research_Log/Correction_Log.md` | The complete methodological audit trail — every finding, every correction, every before/after number, including one mid-pass finding that was itself caught and retracted |
| `Research_Log/Reproducibility_Package.md` | An index of every artifact needed to reproduce the reported numbers, plus an explicit list of what's genuinely not recoverable (e.g. no raw generated-rule text survives for the primary benchmark) |
| `Research_Log/*.md` (the rest) | Scoping documents for each experimental condition (C2/C3/C4), the Section 22 statistical methodology, the pre-registration checklist, data integrity principles, implementation history, and dataset curation history |
| `pipeline/` | All dataset-curation, generation-orchestration, scoring, and statistical-analysis code |
| `benchmark/` | The frozen 299-case manifest, ground-truth exclusion reasoning, variant line-range annotations, and the full per-case source (vulnerable/patched/transformed variants + patch diff) for every case |
| `analysis_reports/` | Plain-text output of the formal statistical analysis (original and corrected) and the explicit end-to-end metric tables |
| `model_catalog/` | The verified open-weight model list and how models were grouped for role assignment |
| `autogrep_fork_diff/` | Our changes to Autogrep, as diffs against the pinned upstream commit — not a redistributed copy of the tool itself |

## What's deliberately not included

- **Raw per-call execution logs** (hundreds of thousands of individual generation/validation/sample
  records). The curated summary reports in `analysis_reports/` and the figures in
  `Paper_Draft_Notes.md` are derived from these; the raw logs are available on request.
- **The raw dataset-mining corpus** (tens of thousands of candidate patches screened down to the
  final 299 cases) — only the final, frozen case set is included here.
- **Institutional infrastructure details** (GPU host names, VM access procedures) — not needed to
  understand or extend the analysis.
- A handful of the 299 cases embed real-looking credential strings as part of the vulnerability
  under test (e.g. a hardcoded API key, copied from the original public repository, is literally
  what CWE-798 cases exist to test) — these have been replaced with an obvious placeholder; the
  vulnerability pattern itself is unchanged.

## Headline results (see `Research_Log/Paper_Draft_Notes.md` for full detail and caveats)

- Every MCC/VGR number reported throughout this study is **conditional** — computed only among cases
  where a rule was actually accepted. The explicit end-to-end tables (§7.9) show that even the
  best-performing condition solves fewer than 1 in 16 requested cases completely end-to-end.
- A large, consistent conditional-MCC gain from feedback-driven repair over one-shot generation is
  real and reported — but repeating the same comparison on the end-to-end metric (same case
  population for every condition, repository-aware statistical testing) finds **no statistically
  detectable difference in any of the 8 models tested**. This document does not claim repair
  produces an established end-to-end quality improvement; conditional MCC and end-to-end success are
  reported as two distinct, non-interchangeable results throughout.
- Multi-agent causal claims (does separating roles across models help?) are reported as hypotheses
  consistent with the observed data, not confirmed findings — formal significance testing finds no
  statistically detectable pairwise difference among the four multi-agent configurations tested.
- Conclusions are explicitly scoped to the tested Autogrep implementation and wrapper as configured
  in this study, not to "LLM-to-Semgrep rule generation" as a general capability claim (see
  `Paper_Draft_Notes.md` §10 for why).

## Reproducing the analysis

`Research_Log/Reproducibility_Package.md` lists the exact script run order against the retained data.
Note that re-running the full pipeline from scratch requires the raw per-call logs (not included
here, see above) or a fresh generation run against the included dataset and pipeline code.
