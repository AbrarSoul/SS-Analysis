"""
Section 9 ground-truth test bundle: CASE-0008
(parisneo/lollms-webui, CVE-2024-8898, CWE-22 -- path traversal).

The real patch touches three endpoints (install_app, uninstall_app,
lollms_assets). In THIS vulnerable_source.py snapshot, uninstall_app and
lollms_assets already sanitize their path-derived parameters via existing
sanitize_path() calls elsewhere in the file (file_name at line 505 for
lollms_assets); the one clean, unambiguous, still-missing-sanitization
sink is install_app(): app_name is taken straight from the URL path and
used to build filesystem paths (app_path, source_dir) with no validation
at all. This bundle targets that specific sink as the representative
instance of the vulnerability mechanism (Section 9.3).

Uses line-index slicing (not literal string matching) to avoid trailing-
whitespace mismatches between this script and the source file.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0008"
original_lines = (CASE_DIR / "vulnerable_source.py").read_text().splitlines(keepends=True)

# 0-indexed: lines 339-351 (1-indexed) == indices 338-350
START, END = 338, 351
block = original_lines[START:END]
assert block[0] == '@router.post("/install/{app_name}")\n'
assert block[-1].strip() == 'raise HTTPException(status_code=404, detail=f"App {app_name} not found in the local repository")'


def rebuild(new_block_lines):
    return "".join(original_lines[:START] + new_block_lines + original_lines[END:])


original = "".join(original_lines)

# --- Variant 1: renamed vulnerable variant ---
# Rename app_name -> application_name throughout install_app() (signature,
# path decorator placeholder, and all 3 uses in the body). Same exact
# vulnerability: no sanitization before building filesystem paths.
renamed_block = [line.replace("app_name", "application_name") for line in block]
renamed_source = rebuild(renamed_block)
assert renamed_source != original
assert "async def install_app(application_name: str" in renamed_source
assert '@router.post("/install/{application_name}")' in renamed_source
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: equivalent API-call formatting -- .joinpath() instead of the
# / operator. Same exact vulnerability, no renaming.
structural_block = [
    line.replace(
        "app_path = lollmsElfServer.lollms_paths.apps_zoo_path/app_name",
        "app_path = lollmsElfServer.lollms_paths.apps_zoo_path.joinpath(app_name)",
    ).replace(
        "source_dir = REPO_DIR/app_name",
        "source_dir = REPO_DIR.joinpath(app_name)",
    )
    for line in block
]
structural_source = rebuild(structural_block)
assert structural_source != original
assert ".joinpath(app_name)" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (app_name can no longer escape
# the intended directory) but via an explicit inline rejection check for
# ".."/"/"/"\\" instead of calling the imported sanitize_path() utility --
# a materially different mechanism, not byte-identical to the known fix.
safe_block = list(block)
insert_at = next(i for i, l in enumerate(safe_block) if "check_access(" in l) + 1
safe_block.insert(
    insert_at,
    '    if ".." in app_name or "/" in app_name or "\\\\" in app_name:\n'
    '        raise HTTPException(status_code=400, detail="Invalid app name")\n',
)
safe_source = rebuild(safe_block)
assert safe_source != original
assert 'if ".." in app_name or "/" in app_name or "\\\\" in app_name:' in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a new endpoint with the
# same superficial shape (apps_zoo_path / <name>, os.makedirs) but the
# path component is a hardcoded literal, never derived from user input --
# genuinely safe regardless of what any caller sends.
BENIGN_ADDITION = '''
@router.post("/install_default")
async def install_default_app(auth: AuthRequest):
    """Installs a fixed, hardcoded default app.

    The path component here is a compile-time constant, never derived
    from user input, so no path traversal is possible, unlike
    install_app()'s app_name parameter.
    """
    check_access(lollmsElfServer, auth.client_id)
    app_path = lollmsElfServer.lollms_paths.apps_zoo_path / "default_starter_app"
    os.makedirs(app_path, exist_ok=True)
    return {"status": True}

'''
benign_source = safe_source.replace(
    '@router.post("/install/{app_name}")',
    BENIGN_ADDITION.strip("\n") + '\n\n@router.post("/install/{app_name}")',
    1,
)
assert benign_source != safe_source
assert "install_default_app" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)

print("Wrote 4 new samples for CASE-0008.")
