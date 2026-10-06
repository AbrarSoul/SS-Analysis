# Phase 2 Dataset Curation Log: Steps 1–4 (Import, Filter, Deduplicate, Verify)

*A complete, chronological record of this session's work, written for use as source material for the paper's Methods section. Picks up where `Implementation_Log.md` (Phase 1) left off.*

---

## 1. Starting point

Phase 1 (infrastructure) was complete and verified. The MoreFixes v4 patch-file zip (`patch-files2026-06-20.zip`, 52,723 real patch files) had already been downloaded in a previous session and was confirmed still present and untouched. Today's task was design doc Section 8, Steps 1–2: import and filter the candidates, then deduplicate them.

Before writing any code, the exact current wording of the design doc's Sections 6 (dataset size/partitioning), 7 (inclusion/exclusion criteria), and 8 (the seven-step curation procedure) was re-read directly from the file, rather than relied on from memory, to avoid drifting from what the frozen document actually specifies.

## 2. A gap discovered before filtering could properly start

Planning the filtering step surfaced a real problem: the patch-file zip only encodes `owner/repo/commit` in each filename. It carries no CVE identifier, no GHSA identifier, and no CWE classification at all. Without that information, two requirements from the design doc could not be satisfied:

- Section 7.1's inclusion criterion: "It has a public CVE or GHSA identifier."
- Section 6.2's requirement to report the CWE distribution of the final dataset.

This metadata only exists in MoreFixes' *other* file — the SQL database dump — which had deliberately not been downloaded previously (it was judged unnecessary for the pipeline itself). That earlier judgment turned out to be incomplete: it's not needed by the generation pipeline, but it *is* needed to correctly curate the dataset in the first place.

## 3. Setting up a local database to hold the metadata

**Checked what was available locally:** no native `psql`/PostgreSQL install, but Docker and `sqlite3` were present.

**Docker was chosen** as the path forward (a disposable, easy-to-tear-down local database, rather than installing PostgreSQL directly on the machine). The Docker CLI was present but its background service (Docker Desktop) wasn't running; started it (`open -a Docker`) and polled until it responded, which took under two minutes.

**Downloaded the SQL dump** (`dump-2026-06-20.sql.gz`, ~3.3GB) using `zenodo_get`, and **started a Postgres 16 container** in parallel — two independent background tasks running at the same time rather than sequentially, to avoid idle waiting.

**While both were running**, used the time productively rather than waiting idle:
- Wrote and ran an offline analysis script that reads the patch zip's 52,723 entries directly from the archive (without extracting anything to disk) and classifies each one by programming language, reusing Autogrep's own language-detection logic (`patch_processor.py`'s file-extension map) so the classification would be consistent with what the actual generation pipeline recognizes. This produced the first real numbers: 15,673 patches touch at least one target language (Python, Java, JavaScript, or TypeScript).
- Fetched the MoreFixes project's own data-dictionary documentation from its GitHub repository to learn the exact database schema (table names, columns, and how they relate) *before* the database was even ready to query — so the actual queries could be written correctly the first time rather than through trial and error.

**Once both background tasks finished:** confirmed the Postgres container was running, then restored the dump by streaming the decompressed SQL directly into it (`gunzip -c dump.sql.gz | docker exec -i ... psql`), which avoided writing a second, much larger, uncompressed copy of the file to disk. The restore completed with zero errors.

**Verified the restore actually worked**, rather than trusting a clean exit code alone: queried row counts across every one of the 9 tables (`fixes`: 567,067 rows; `cve`: 355,018; `cwe_classification`: 397,746; `commits`: 50,986; `file_change`: 129,070; `repository`: 10,377; `method_change`: 253,503; `cve_project`: 105,857; `cwe`: 1,394).

## 4. Understanding what the numbers actually meant

The `cve` table's row count (355,018) was far larger than the "43,357 unique CVEs" the dataset's own description claims. Rather than assume this was an error, investigated it: the `cve` table turns out to store a broad mirror of vulnerability records (most without any commit fix ever mapped to them), while the `fixes` table is the actual CVE-to-commit join table relevant to this work.

Querying `fixes` directly showed 78,654 distinct CVEs and 340,154 distinct commits associated with it — *still* higher than the dataset's stated totals. Checking the `score` column explained why: `fixes` contains every *candidate* mapping an automated tool ("Prospector") proposed, most at low confidence (scores 2–234), plus a smaller set of high-confidence direct matches (score exactly 1337, of which there were 30,533). The dataset's official published totals (43,357 CVEs, 52,672 patches) refer to a *curated, exported subset* of these candidates — the actual patch-file zip — not the full candidate table sitting in the database.

This mattered practically: rather than trying to reverse-engineer which score threshold MoreFixes used internally to decide what got exported, the correct and much simpler approach was to match our *real, already-downloaded* patch files against `fixes` directly by their exact (repository, commit hash) — sidestepping the question entirely, since we only care about the metadata for patches we actually have.

## 5. Joining candidates to their CVE and CWE identity

Wrote a script to load the 15,673 language-filtered candidates into a temporary database table and join them against `fixes` (for CVE id and match confidence) and `cwe_classification`/`cwe` (for CWE id and name).

**First attempt failed.** The join query used psql's `\copy` command to export results as CSV, but `\copy` is a client-side meta-command that must fit on a single line when read from a script — the query spanned multiple lines, and the failure was silent: no CSV data came out, just the setup statements' own status messages. Diagnosed by inspecting the malformed output file directly.

**Fixed** by switching to the SQL-level `COPY (...) TO STDOUT` command instead of the psql meta-command — a real SQL statement, not a backslash command, so it isn't restricted to one line. Verified this worked with a small test query before rerunning the full join.

**Result:** 15,655 of 15,673 candidates (99.9%) matched to at least one CVE. The 18 unmatched candidates were set aside separately, since they have no confirmable CVE/GHSA identity and therefore can't satisfy Section 7.1's inclusion criterion.

Spot-checked the actual joined data for sanity rather than trusting the row count alone: confirmed real, current CVE identifiers (including some from 2026), sensible CWE names, and noticed 1,988 patches where a single commit maps to more than one CVE — for example, one `nginx-ui` commit that fixes two separate CVEs at once. Decided to keep all associated CVE ids on these rather than arbitrarily picking one, since the commit genuinely fixes multiple things.

## 6. Deduplication

Checked the design doc's five deduplication criteria (Section 8, Step 2) one at a time against the joined data:

- **Repository + commit hash uniqueness:** confirmed zero collisions, as expected (candidates are inherently keyed by this pair already).
- **Multiple CVEs per patch:** 1,988 cases, consolidated (not dropped — see above).
- **Same CVE reachable via multiple different patches:** 2,839 CVEs. Investigated a concrete example (`1Panel-dev/1Panel`, where three CVEs and three commits are all cross-linked) and concluded this reflects genuinely complex multi-commit security releases, not duplication — logged for case-by-case judgment during the later verification steps rather than resolved automatically now, since collapsing it mechanically risks discarding the actual correct fixing commit for a given CVE.
- **Normalized patch-content hashing** (to catch near-identical or exact-duplicate diffs): found 344 groups of byte-identical content across nominally different (repository, commit) pairs.

**Investigating those 344 groups led to the most important finding of the session.** Sampling a few by hand, one pair stood out: two "different" commit hashes for the same project that differed by only one trailing character. That's not a coincidence a real, independent commit would produce — it looked like a data artifact. Checking systematically for this pattern across all 344 groups (by testing whether one hash is a text-prefix of the other) found 69 suspicious pairs, later refined to 70 with more careful grouping logic.

Examining these showed **three distinct real-world causes**, all producing the same symptom (identical patch content, apparently different commit):
1. **Short hash vs. full hash** — the same commit stored once with an abbreviated hash and once with the full 40-character SHA.
2. **Repository name casing** — e.g. `Automattic/mongoose` vs. `automattic/mongoose`, the same repository under GitHub's case-insensitive naming.
3. **Repository renames or ownership transfers** — e.g. `hwchase17/langchain` was later transferred to `langchain-ai/langchain`; GitHub preserves commit history (and hashes) across such transfers, so the same commit appears to "belong" to two different repository names depending on when it was recorded.

These are not independent near-duplicate patches — they are the *same underlying fix*, recorded twice. The dedup script was rewritten (an earlier, hastily-edited version was caught mid-edit as broken — it contained a stray early `return` that would have silently skipped most of the logic — and was discarded in favor of a clean rewrite rather than patched further) to explicitly detect and separate this category from genuine content collisions.

**Final treatment:** the 70 same-commit-different-representation cases were excluded outright (keeping whichever representation had the fuller commit hash), each with a specific logged reason and a record of which file was kept instead. The remaining 274 groups — genuinely different commits that happen to produce identical patch content — were *not* excluded, since a small or simple patch can coincidentally collide without being a true duplicate; these were flagged for case-by-case review during the later advisory-verification steps instead.

## 7. Final verification and results

Re-checked "patch availability" (Section 8 Step 1's requirement) specifically against the final surviving candidate set, rather than assuming the earlier whole-zip check still applied after all the filtering: confirmed all candidates are present in the zip, none empty, none suspiciously small.

Generated final summary statistics and cross-checked them against the design doc's own targets:

| Stage | Count |
|---|---:|
| Total patches in MoreFixes v4 | 52,723 |
| Touch at least one target language | 15,673 |
| Matched to a CVE identity | 15,655 |
| After deduplication | **15,585** |
| Distinct CVEs represented | 14,461 |

**Language breakdown** (Python 5,592 / JavaScript 4,305 / Java 3,949 / TypeScript 2,465) comfortably exceeds the 100-per-language target for the eventual 300-case final set, with substantial headroom for further attrition during advisory verification.

**CWE coverage** against every category Section 6.2 asks for was checked explicitly, not assumed: cross-site scripting (2,392), path traversal (1,033), information exposure (714), SQL/command/code injection combined (1,450), authorization/access-control issues combined (1,186), server-side request forgery (499), unsafe deserialization (420), authentication problems (368) — every listed category has meaningful representation. Only 63 of 15,585 candidates (0.4%) have no CWE mapping at all.

## 8. Artifacts produced

All under `data/morefixes_v4/`:
- `target_language_candidates.txt` — the 15,673 language-filtered candidates
- `candidates_with_cve_cwe.csv` — the CVE/CWE join result (19,776 rows — one per patch×CVE pair, since some patches map to more than one CVE)
- `dedup_log.csv` — every multi-CVE, multi-patch, and near-duplicate-content pattern found, informational only, no exclusions implied
- `dedup_exclusions.csv` — the 70 actual exclusion decisions, each with its specific reason and which file was kept instead
- `candidates_deduplicated.csv` — the final 15,585-row eligible candidate table

Scripts written, all in `pipeline/`: `analyze_morefixes_zip.py`, `map_candidates_to_cve_cwe.py`, `dedupe_candidates.py`.

**A standing piece of infrastructure now exists as a side effect of this work:** the local Postgres container holding the full MoreFixes v4 database. Beyond today's task, this will also be useful later — the `file_change` table's `code_before`/`code_after` columns hold complete source-file content, not just diff hunks, which is a genuine upgrade opportunity for Section 8 Step 5 (extracting fuller vulnerable/patched context) once curation reaches that point.

## 9. Steps 3–4: retrieving repository states and verifying against real advisories

### 9.1 Selecting a working batch, not all 15,585

Doing Steps 3–4 (real repo clones, real advisory verification) against all 15,585 candidates would be wildly disproportionate — only 380 cases are ever needed. Since the design's own phasing treats the 30-case pilot as a separate, earlier deliverable from the 300-case final set (Section 29), today's realistic scope was narrowed to: get to a clean, verified 30-case pilot, oversampled to allow for attrition.

Selected 96 candidates (24 per language), applying criteria not yet used: single-file changes only (Section 7.1's stated preference — and the only point where this actually gets enforced, since Phase 1 confirmed Autogrep itself does not), highest-confidence CVE match only (`score == 1337`, a direct match rather than a heuristic guess), excluding anything already flagged in the near-duplicate-content review list, and stratified across distinct CWE categories within each language rather than clustering on the single most common one. Verified beforehand that each language has hundreds of candidates meeting even this strict bar (269–875 per language), so the batch size wasn't resource-constrained.

### 9.2 Step 3: repository states

Built a script reusing Autogrep's own `GitManager`/`PatchProcessor` for cloning and commit resolution (rather than reimplementing), but extracting **complete file content at both revisions via direct git checkout**, and the **real `git diff` output**, instead of the delta-only reconstruction the earlier bulk zip-scan used — a genuine fidelity upgrade now that this is being done per-case rather than across 52,723 patches at once.

One correctness decision made explicitly: a merge commit's "vulnerable parent" is not assumable as `parents[0]` — which parent represents the actual pre-fix state isn't guaranteed by that convention. Merge commits are flagged for separate handling, not guessed.

**A real operational problem caught before it caused damage:** the initial run only wrote its output at the very end of the loop. Full clones of real, sometimes large repositories (`apache/spark`, `jenkins`, `mattermost`, `liferay-portal`) meant the whole run would very likely exceed the background task time budget, and an unfinished run would have silently discarded everything completed so far. Stopped the run after only 2 repos (cheap to redo), rewrote the script to write each result incrementally and skip already-completed entries on a restart, then reran from scratch.

**Result after all 96:** 77 fully extracted and ready, 4 excluded with specific reasons (2 repos inaccessible, 1 file added rather than modified, 1 unparseable), 15 flagged as merge commits pending separate review. Per-language breakdown of the 77: JavaScript 20, TypeScript 20, Python 19, Java 18 — comfortably above the 10-per-language target even before Step 4.

### 9.3 Step 4: verifying against real advisories

Fetched the actual GitHub Security Advisory record for every surviving case's CVE (via the authenticated `gh api`, not scraping), recording not just whether a record exists but whether it's a **GitHub-reviewed** advisory or merely an auto-imported, staff-unreviewed one — a distinction the design doc's own source-priority ordering (Section 5.3) cares about, and one that's easy to miss if you only check "does an advisory exist."

Also ran a conservative, honest heuristic for refactor-only changes (every changed line is blank, a comment, or an import) — flagged exactly 1 of 77 for review, not auto-excluded, since this is a cheap proxy, not a real judgment.

**A second real bug, caught the same way as the first — by not trusting a suspiciously clean result:** 15 of 77 cases came back with "no advisory found" from GitHub's API. Rather than accepting this (which would have excluded a fifth of our surviving high-confidence batch), spot-checked one directly: NVD has a complete, real record for it. The discrepancy is genuine and informative — MoreFixes' "direct GHSA match" label reflects provenance at the time it was collected, not a guarantee the record is still live-discoverable via GitHub's API today. Built an NVD fallback for these 15 specifically (Section 5.3 ranks NVD below a GitHub-reviewed advisory but still above MoreFixes' own metadata as evidence).

That fallback's first run reported 0 of 15 confirmed — which contradicted a CVE already manually confirmed to be real seconds earlier via `curl`. Not a data problem: Python's `urllib` on this machine couldn't locate a local CA certificate bundle, and the exception handler was silently converting every one of those failures into "not found." Fixed by explicitly pointing the SSL context at the `certifi` package's bundle (keeping full certificate verification on — disabling it would have been the wrong fix for a script whose entire purpose is checking the authenticity of external data). Rerun: **all 15 confirmed as real CVEs.**

**Net result: all 77 surviving cases now have independently confirmed, real external evidence** (62 via a live GitHub advisory, 15 via NVD) — not just MoreFixes' own internal classification.

### 9.4 What's next within Steps 3–4

The automated portion is done. What's left is the part that was always going to require actual reading, not more scripting: comparing each candidate's real diff against its real advisory description, checking the five criteria Section 8 Step 4 lists (matches the advisory, parent is genuinely vulnerable, child is genuinely fixed, the change isn't pure refactoring, the security-relevant lines can be pinned down) — and narrowing the surviving pool down to the final 10-per-language, 30-case pilot.

## 10. Manual verification and the final pilot compilation

### 10.1 Why this couldn't be scripted

Section 8 Step 4's core requirement — does the actual code change correspond to what the advisory describes — cannot be verified by automated CWE-matching or keyword heuristics alone. This was proven directly during the automated pass (Section 9.3): CWE agreement was clean (0 disagreements flagged) across candidates that, on actual reading, included at least six clear advisory/diff mismatches. So every one of the 96 surviving candidates was read directly: the real advisory description against the real diff, checking whether the change plausibly causes and then fixes the described vulnerability, whether it's substantive rather than cosmetic, and whether the single selected file actually contains the security-relevant change (not, for instance, a test file while the real fix lives elsewhere).

### 10.2 Results per language

Reviewed all candidates language by language, stopping once 10 solid, unambiguous cases were confirmed per language (each had 13-24 candidates available, so there was room to be selective rather than accept borderline cases):

- **Python**: 10 confirmed from 19 reviewed. Two rejected outright: one candidate's diff (`PheonixAppAPI`) only changed log-message strings while the advisory described an exposed encoding map — no relationship at all; another (`hyperledger/indy-node`) had a test file as its single recognized-language file, while the advisory's own implementation notes pointed to a completely different production file not present in the diff.
- **Java**: 10 confirmed from 18 reviewed, keeping only one of three near-identical `jackson-databind` deserialization-blacklist cases for diversity. One rejection (`apache/lucene-solr`) is notable: it had already been flagged by the automated refactor-only heuristic (Section 9.3), and manual reading confirmed the heuristic was right — the diff only edits a Javadoc comment.
- **JavaScript**: 10 confirmed from 15 reviewed. Two rejections: one `anything-llm` case (different CVE than the one already accepted from the same repo) only added a trailing period to an already-identical error message, while the advisory specifically described *different* error messages depending on username existence — the actual enumeration-fix logic isn't in this diff at all. `brokercap/Bifrost`'s diff fixed an unrelated client-side JavaScript variable-name bug, while its advisory describes a server-side authentication-header bypass.
- **TypeScript**: 10 confirmed from 14 reviewed. One clear rejection: `mattermost/mattermost`'s advisory describes a missing permission check when deleting Boards comments; the diff only changes a React `useEffect` dependency array in an unrelated user-profile component — no connection to the described vulnerability at all.

### 10.3 A scope decision: 40 cases, not 30 (confirmed final)

The design doc's Section 6.1 groups JavaScript and TypeScript into one combined category for the 300-case final set. Candidates were verified per-language separately during the pilot (10 each for Python, Java, JavaScript, and TypeScript), which produces 40 cases rather than the 30 originally specified for the pilot partition.

This was discussed explicitly rather than left as an unexamined inconsistency. Two questions were separated: (1) should the *pilot* keep JS and TS split, and (2) should the same split propagate to the *300-case final set* (which would mean 400 cases total, and a ~33% increase in final-set curation and benchmark-execution cost). Decision: **keep the pilot at 40** (JS/TS split) — the work was already done and independently verified, and the pilot's actual purpose (prompt development, model screening) genuinely benefits from seeing JS-specific vs. TS-specific behavior separately. **Keep the final set at 300** (JS/TS combined, as originally specified) — the final set answers the locked research questions, not model/prompt development, and any JS-vs-TS difference worth reporting there can be handled as a subgroup breakdown within the combined 100 (Section 19 already calls for per-language subgroup analysis) rather than doubling the final-set cost to get separate top-line numbers. Design doc Section 6.0.1 updated to record both halves of this decision as final, not tentative.

### 10.4 Final compilation

Compiled all 40 verified cases into the design doc's Section 10 `benchmark/` structure: one directory per case (`CASE-0001` through `CASE-0040`) containing `metadata.json`, `patch.diff`, and the complete `vulnerable_source`/`patched_source` file content (not diff-derived reconstructions — the real files, extracted directly via git in Step 3), plus a top-level `manifest.jsonl`, `inclusion_log.csv`, and `exclusion_log.csv` recording every Step 4 rejection with its specific reason.

**Final pilot dataset: 40 cases — 10 Python, 10 Java, 10 JavaScript, 10 TypeScript — every one individually verified against a real, independently-fetched advisory (GitHub Security Advisory or NVD), not just matched by MoreFixes' own internal classification.**

## 11. Status: the 30-case pilot (expanded to 40) is complete through Section 8, Steps 1–4.

**Section 8, Steps 1–4 are done for the pilot partition.** The 40-case pilot dataset is fully compiled at `benchmark/cases/` with a complete manifest, inclusion log, and exclusion log — every case individually verified against a real, independently-fetched advisory, not just MoreFixes' internal classification.

**Not yet done, for later sessions:**

- **The 15 merge-commit cases** set aside during Step 3 remain unresolved — worth revisiting if more pilot cases are ever needed, or folded into the 300-case final-set curation later.
- **The 50-case multi-agent development partition and the 300-case final evaluation set** (Section 6) haven't been started at all — this session's work covered only the pilot. The same curation machinery (language filtering, CVE/CWE joining, deduplication, repository-state extraction, and now Steps 5–7's context extraction/difficulty classification/freezing scripts) is reusable for both, but Step 4's advisory verification will need to scale well beyond manual, read-every-diff work once hundreds of cases are involved.

(Section 9's six-sample ground-truth test bundle, listed as outstanding in an earlier draft of this section, is now complete — see Section 12. Section 8, Steps 5–7 are also now complete for the pilot — see Section 13.)

## 13. Section 8, Steps 5–7: model context extraction, difficulty classification, and freezing the pilot manifest

Picked up in a new session. Before writing any extraction code, re-read Section 8's Steps 5–7 wording directly from the frozen design doc rather than from memory, and surfaced the one real open design decision in Step 5 ("Define a shared maximum context limit. Truncate using one deterministic policy") to the user rather than picking a number unilaterally — no context-window data existed anywhere in the repo to derive one from, and the file-size spread across the 40 cases turned out to be extreme (11 to 2,814 lines). The user chose a 12,000-character shared budget.

**CWE definitions (a Step 5 prerequisite).** 37 distinct real CWE IDs appear across the 40 cases (plus NVD's `NVD-CWE-noinfo` placeholder for CASE-0024, which genuinely has no CWE assigned in its public record). Rather than trust memory for all 37 official titles on a piece of data going into a frozen research artifact, every one was verified by fetching `cwe.mitre.org/data/definitions/<id>.html` directly. This caught two titles that had been renamed since an earlier CWE version and would otherwise have been wrong: CWE-598 ("Use of GET Request Method With Sensitive Query Strings" → current title "Use of HTTP Request With Sensitive Query String") and CWE-300 (dropped the "('Man-in-the-Middle')" suffix). Saved to `benchmark/cwe_definitions.json` with its source and verification date recorded.

**Step 5: extracting the vulnerable/patched function, imports, and containing class per case.** The natural first instinct — a fresh AST-based "find the function" pass per language — ran into real trouble for JavaScript/TypeScript specifically: several cases' vulnerable code lives inside anonymous callbacks, builder-chain arguments (tRPC procedures, ssh2 connection config objects), a `switch`-case fragment inside one large handler, or isn't inside any function at all (a module-level object literal, a class decorator's config). A "smallest enclosing named function" heuristic doesn't have a good answer for most of these.

The approach that actually worked, once found: reuse the byte-exact, already-verified vulnerable-region text that Section 9's `build_bundle_case*.py` scripts already contain for every one of the 40 cases (each one was hand-built and passed real syntax-check assertions earlier today) as ground truth, rather than re-deriving function boundaries from scratch.
- **Python (10 cases):** the stdlib `ast` module, keyed by `(function_name, class_name, occurrence_index)`, with a real assertion if the expected match count isn't found — this caught nothing wrong on the first run, but correctly disambiguated CASE-0007's two identically-named `initialize()` methods by class.
- **Java (10 cases):** no parser was readily available, so a hand-written brace-matching scanner (aware of string/char literals and `//`/`/* */` comments, so braces inside them don't corrupt the depth count) anchored on each case's known method/static-block signature. Verified correct on CASE-0011's ~90-line denylist static block (containing many string literals with escaped characters) and on CASE-0020, whose patched version's method signature gained an extra parameter — required loosening the anchor pattern to match the method name only, not the full parameter list.
- **JavaScript/TypeScript (20 cases):** the same brace-matching approach, extended with template-literal handling (tracking backtick-string mode and `${...}` interpolation as its own nested real-code region, so braces inside interpolated expressions are counted correctly without corrupting the outer function's depth), anchored on a character-offset position rather than a line number. This caught two real bugs during construction, both from the same root cause — a destructured-parameter brace pair on the *same line* as the real body-opening brace was being mistaken for the target block, because the scanner returned as soon as depth first hit zero rather than distinguishing the parameter pattern's self-contained `{...}` from the actual body: CASE-0025's `function searchWithRipgrep({ ...params }) {` (fixed by anchoring past the closing `}) {` of the parameter list) and, differently, CASE-0031's `.query(async ({ input, ctx }) => {` (fixed by switching from line-based to exact-substring-based anchoring). A separate bug in class-declaration detection — returning the *first* class in the file rather than the one actually enclosing the target — was caught on CASE-0032, which has two classes (`KeyboardInteractivePrompt` declared before the real target's class, `SSHSession`); fixed by computing each candidate class's full brace-matched span and picking the innermost one that actually contains the anchor position.

Three cases needed genuine special-casing rather than fitting the brace-matcher: CASE-0010 (Python, a 16-line module-level script with no function or class at all — the whole file is the relevant unit), CASE-0026 (JS, a bare module-level `const Namespaces = {};` statement, no enclosing function), and CASE-0034 (TS, a class decorator's configuration object, where the "class" is declared *after* the anchor rather than around it, requiring a forward search instead of the normal enclosing-span search).

Every one of the 40 extractions was spot-checked against known content (e.g., confirming CASE-0011's vulnerable extract excludes the missing denylist entry while the patched extract includes it; confirming CASE-0030's patched extract contains the added length guard) rather than trusted on the strength of "it ran without an assertion error."

**Truncation.** Applying the confirmed 12,000-character budget (diff truncated first, then the patched function, then the vulnerable function — each from the end, imports and the class-declaration line never truncated) triggered on exactly 3 of 40 cases: CASE-0011 (18,627 → 12,000), CASE-0016 (16,262 → 12,000), and CASE-0030 (22,615 → 12,000, the largest single function in the pilot at 380 lines). In all three, only the diff and/or patched function were touched — the vulnerable function itself, the one field a model absolutely needs intact to do the task, was never truncated in any case, confirmed by checking `'TRUNCATED' not in vulnerable_function` for all three afterward.

**Step 6: difficulty classification.** Language, CWE, changed-lines/changed-files, and function size are computed directly (all 40 cases are single-file patches, consistent with the design's primary-benchmark preference). `supported_status` reuses `semgrep_representability` from Step 4 (already "supported" for all 40). The two judgment fields — `pattern_or_taint` (can a Semgrep rule flag this via a local syntactic match, or does it need to trace a value from an untrusted source to a sink) and `structural_or_context_heavy` (is the vulnerable pattern self-contained, or does correctly distinguishing it from a safe look-alike require broader context) — were classified individually for all 40 cases from this session's own hands-on construction of each case's Section 9 ground-truth bundle earlier today, where exactly this distinction (what makes the `benign_lookalike.*` file safe despite looking similar) had already been worked out in detail per case. Resulting split: 25 pattern / 15 taint, 21 structural / 19 context-heavy — a reasonably balanced spread across both axes, not skewed to all-easy.

**Step 7: freezing the pilot manifest.** SHA-256 of every artifact in every case directory (10 files per case, uniformly, after removing 10 stray `__pycache__` directories left behind by Section 9's `py_compile` syntax checks and excluding that byproduct class from hashing going forward), a case-level hash over each case's sorted artifact hashes, and one dataset-level hash over all 40 case-level hashes (`929893ca65cee426ea085f4953efdc610c5a8f5d3c4eccb4399fa8064caf23cf`) as the pilot partition's frozen fingerprint. Written to `benchmark/manifest_frozen.jsonl` (merging the existing per-case metadata with Steps 5–6's new fields: `changed_function`, `vulnerable_lines`, `context_complexity`, `pattern_or_taint`, `patch_size_added`/`patch_size_deleted`, `artifact_hashes`) and `benchmark/freeze_record.json`.

Four fields from Section 10's example schema were **not** populated and are recorded as a known, explicit gap rather than silently dropped or filled with invented values: `ghsa_id`, `advisory_date`, `repository_license`, `source_urls`. Nothing in Steps 1–6 of the curation work collected these, and fabricating plausible-looking values for a frozen artifact would be worse than an honest absence. If they're needed later (e.g. for a "license compliance" appendix), they'd need a dedicated pass — likely straightforward to backfill from the same `gh api` advisory lookups Step 4 already used, plus one GitHub API call per repository for its license.

**Artifacts produced this session:** `pipeline/extract_context_python.py`, `pipeline/extract_context_java.py`, `pipeline/extract_context_js_ts.py`, `pipeline/apply_context_budget.py`, `pipeline/classify_difficulty.py`, `pipeline/freeze_manifest.py`; `benchmark/cwe_definitions.json`, `benchmark/model_context/CASE-*.json` (40), `benchmark/difficulty/CASE-*.json` (40) + `benchmark/difficulty_summary.json`, `benchmark/manifest_frozen.jsonl`, `benchmark/freeze_record.json`.

**Status: Section 8 (Steps 1–7) is now fully complete for the 40-case pilot partition.**

## 12. Section 9: the six-sample ground-truth test bundle, all 40 pilot cases

Following the one worked example built and reviewed earlier (CASE-0009), the user confirmed to proceed straight through the remaining 39 cases using the same methodology, without pausing for per-case sign-off.

**Method.** For each case, four new samples were added alongside the existing `vulnerable_source.*`/`patched_source.*` pair, bringing every case to the full six required by Section 9's table (original vulnerable, original patched, renamed vulnerable variant, structurally changed vulnerable variant, transformed safe variant, benign structural look-alike):

- Each case's `patch.diff` was read first to identify the exact vulnerable lines, then the corresponding region of `vulnerable_source.*` was read directly (not assumed) to get byte-exact context, including whitespace style (tabs vs spaces — this varied case by case and caused two early script failures, in CASE-0008 and CASE-0011, from typing literal blocks that didn't match trailing whitespace or embedded-substring boundaries in the real file).
- All four transformations per case were produced by a small, dedicated, deterministic Python script (`pipeline/build_bundle_case00NN.py`) that does exact string/line-based substitution on the real vulnerable source — never by asking a model to freely rewrite the file. This satisfies Section 9.2's explicit requirement: "Do not allow an evaluated model to certify its own test variants. Prefer deterministic transformation templates and executable checks." Each script asserts its expected input text is present before transforming, and asserts specific expected output afterward, so a silent no-op edit or a wrong-location edit fails loudly rather than producing a mislabeled sample.
- Renamed and structurally-changed variants preserve the exact vulnerable mechanism (same sink, same missing check, same predictable value, etc.) while changing identifiers or code shape, per Section 9.1's permitted-transformation list (variable/function renaming, intermediate-variable introduction, equivalent conditional rewriting, equivalent API-call formatting, wrapper-function introduction, safe statement reordering).
- Safe variants apply a fix with the same security property as the real patch but expressed differently (different helper structure, different threshold/wording, different but equally valid API) — deliberately not byte-identical to `patched_source.*`, so a rule can't pass by memorizing the one known fix string.
- Benign look-alikes add a new, clearly-commented function/method that superficially resembles the vulnerable pattern (same API call, same general shape) but is genuinely safe for a stated, verifiable reason (non-sensitive data, hardcoded non-attacker-controlled input, different trust boundary, etc.) — built on top of each case's safe variant.
- Several cases (CASE-0001, 0006, 0008, 0011, 0013, 0016, 0018, 0019, 0022, 0025, 0027, 0036, 0037) had more than one textually-similar vulnerable site in the same file, but the real advisory/patch only fixed one specific instance; in every such case the bundle explicitly targets only the confirmed, patch-verified instance and leaves sibling occurrences untouched, per Section 9.3 ("A report elsewhere in the file does not automatically count as detection of the target CVE" — the inverse principle applied to bundle construction: don't fabricate a labeled vulnerability where the real fix didn't confirm one).

**Verification.** Every one of the 160 new files (40 cases × 4 samples) was syntax-checked with a real toolchain appropriate to its language, not just eyeballed:
- Python: `py_compile`.
- Java: a wrapper script (`pipeline/check_java_syntax.sh`) that copies the snippet to a temp file named after its public class (required by `javac`) and greps for genuine syntax-error diagnostics, ignoring the "cannot find symbol"/"package does not exist" errors expected from single-file extracts of large multi-module projects with no classpath.
- JavaScript: `node --check`.
- TypeScript: a wrapper script (`pipeline/check_ts_syntax.sh`) around a locally-installed `tsc --noEmit`, greeping for `TS1xxx` (genuine syntax) errors only and ignoring `TS2xxx`/`TS7xxx` (missing-import/missing-type) errors from the same incomplete-classpath cause.

All 160 files passed. A cross-case sweep at the end re-ran every check again from a clean pass over all 40 directories to catch any regression from later edits — none found.

**Records kept.** `benchmark/transformation_manifest.jsonl` holds one line per generated sample (160 total, confirmed by count) recording: which transformation categories were applied, a human-readable description of exactly what changed and why the label still holds, the generating script, and `"certified_by_evaluated_model": false` on every entry. Each case's `metadata.json` gained a `test_bundle` block listing all six sample files with their labels and pointing at the shared manifest.

**Errors caught and fixed during this pass** (kept here since they're the kind of mistake likely to recur if Section 9 work resumes for the 50-case or 300-case sets):
- Typing a literal block with normalized trailing whitespace when the real file had trailing-whitespace-only lines (CASE-0008) — the literal match silently failed. Fixed by switching to line-index slicing from the actual file content instead of retyping blocks by hand for whitespace-irregular files.
- A blind substring rename accidentally touching an unrelated string literal that coincidentally matched the renamed identifier's text — `req.params['filename']` (an Express route-parameter *name*, not the local variable) in CASE-0027, and the `content:` MCP response-object *key* (not the local variable) in CASE-0036. Both fixed by protecting the literal with a sentinel swap, or by targeting only the specific declaration/use-site text rather than a blanket rename.
- A naive `"server".replace("server", "smb_server")`-style rename in CASE-0010 would have corrupted the unrelated substring inside the imported `smbserver` module name; fixed with a `\bserver\b` word-boundary regex instead.
- Two cases (CASE-0004, CASE-0027) had an unrelated sibling identifier sharing a name prefix (`sync_tree_node_queue` vs `sync_tree`; a second, out-of-patch-scope `filename.replace(...)` occurrence) that a blanket "vulnerability count == 0 after fix" assertion would have wrongly flagged as a regression; both were resolved by scoping the assertion to the specific patched occurrence rather than the whole file.
