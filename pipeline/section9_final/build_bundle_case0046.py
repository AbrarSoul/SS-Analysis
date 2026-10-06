"""
Section 9 ground-truth test bundle: CASE-0046
(Cp0204/quark-auto-save, CVE-2026-45229, CWE-915 improperly controlled
modification of dynamically-determined object attributes / mass assignment).

Core vulnerable mechanism: `update()` iterates every key/value pair in the
raw request JSON and writes it into `config_data`, only excluding two
specific keys (`dont_save_keys`, a denylist). Any OTHER server-internal or
sensitive config key -- anything not on that short denylist -- can be
overwritten by an attacker-controlled request body. The fix switches to an
allowlist (`allowed_keys`): only the 7 explicitly-named keys can ever be
written, regardless of what else the request body contains.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0046"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''def update():
    global config_data
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    dont_save_keys = ["task_plugins_config_default", "api_token"]
    for key, value in request.json.items():
        if key not in dont_save_keys:
            config_data.update({key: value})
    Config.write_json(CONFIG_PATH, config_data)'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename update -> apply_config_update, dont_save_keys -> excluded_keys.
# Same exact denylist-based (not allowlist-based) key filtering.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''def apply_config_update():
    global config_data
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    excluded_keys = ["task_plugins_config_default", "api_token"]
    for key, value in request.json.items():
        if key not in excluded_keys:
            config_data.update({key: value})
    Config.write_json(CONFIG_PATH, config_data)''',
)
assert "def apply_config_update():" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting
# (inverted condition with continue instead of a positive if-guard). Same
# exact denylist-based vulnerability, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''def update():
    global config_data
    if not is_login():
        return jsonify({"success": False, "message": "未登录"})
    dont_save_keys = ["task_plugins_config_default", "api_token"]
    submitted_items = request.json.items()
    for key, value in submitted_items:
        is_excluded = key in dont_save_keys
        if is_excluded:
            continue
        config_data.update({key: value})
    Config.write_json(CONFIG_PATH, config_data)''',
)
assert structural_source != original
assert "submitted_items = request.json.items()" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (only accept an explicit set of keys) but a
# materially different implementation: builds the update dict via a
# dict-comprehension intersection against a frozenset, instead of the real
# patch's imperative for-loop with a plain list -- genuinely restricts
# writes to the same kind of allowlist, different code shape.
SAFE_SOURCE = '''ALLOWED_CONFIG_KEYS = frozenset({
    "cookie", "crontab", "push_config", "tasklist",
    "magic_regex", "plugins", "source",
})


def update():
    global config_data
    if not is_login():
        return jsonify({"success": False, "message": "unauthorized"})
    submitted = request.json or {}
    safe_updates = {k: v for k, v in submitted.items() if k in ALLOWED_CONFIG_KEYS}
    config_data.update(safe_updates)
    Config.write_json(CONFIG_PATH, config_data)
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "ALLOWED_CONFIG_KEYS" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (iterate request.json.items(), filter by a key set,
# write into a shared dict) but this sibling only ever updates a small,
# purely cosmetic UI-preferences dict (theme/locale) that carries no
# security-sensitive fields at all -- even accepting every submitted key
# unfiltered here would only let a user change their own theme, not any
# server-internal config -- genuinely safe despite the structural
# resemblance to update().
BENIGN_SOURCE = '''def update_ui_preferences():
    """Per-session cosmetic preferences only -- theme/locale -- never
    touches the shared server config, so accepting every submitted key
    here carries no privilege-escalation risk."""
    if not is_login():
        return jsonify({"success": False, "message": "unauthorized"})
    prefs = session.get("ui_preferences", {})
    for key, value in request.json.items():
        prefs[key] = value
    session["ui_preferences"] = prefs
    return jsonify({"success": True})
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "config_data" not in BENIGN_SOURCE
assert "CONFIG_PATH" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0046.")
