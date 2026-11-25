# `before/` snapshot (slimmed 2026-11-25)

`pipeline/diagnostic_audit.py` copied 5,390 files here at the start of the October diagnostic, so that
every later change could be diffed (the resulting diffs are in `../diffs/`).

Only the two files kept here held content not stored anywhere else: the pre-diagnostic versions of
`pipeline/gptlab_config.py` and `pipeline/rescore_variant_location.py`, which differ from both commit
`32aa53d` and today's files.

The other 5,388 files were removed from the repo because they duplicated something else:
- 4,885 were byte-identical to commit `32aa53d`. Recover any of them with `git show 32aa53d:<path>`.
- 341 were copies of the third-party rules in `autogrep/rules/` (git-ignored).
- 157 were Autogrep's git-ignored cache: a clone of the third-party project aio-libs/aiohttp (155 files,
  which this repo does not redistribute) and 2 bookkeeping files.
- 5 were copies of pipeline scripts identical to the current files.

The full original snapshot is kept outside the repo in `SS_attic_20261125/Research_Log/Diagnostic_20261010/before/`.
