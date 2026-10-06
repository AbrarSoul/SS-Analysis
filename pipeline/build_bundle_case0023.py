"""
Section 9 ground-truth test bundle: CASE-0023
(InternalError503/forget-it, CVE-2015-10103, CWE-835 -- loop with
unreachable exit condition / DoS via unbounded timer interval).

Core vulnerable mechanism: #setForgetTime (minutes between "forget" runs)
is bound only to the generic bulk change handler, which saves whatever
value the user entered with no minimum-value check. A value of 0 (or
negative) makes the background "forget" loop run essentially continuously,
a denial-of-service busy loop. The real fix removes #setForgetTime from
the generic selector list and adds a dedicated handler that clamps/rejects
values below 1.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0023"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = (
    "\t        //Save settings as they are changed.\t\n"
    "\t        $(\"#enableConfirmData, \\\n"
    "\t\t\t#clearDataFrom, \\\n"
    "\t\t\t#dataAppCache, #dataCache, \\\n"
    "\t\t\t#dataCookies, #dataDownloads, \\\n"
    "\t\t\t#dataFileSystems, #dataFormData, \\\n"
    "\t\t\t#dataHistory, #dataIndexedDB, \\\n"
    "\t\t\t#dataLocalStorage, #dataPluginData, \\\n"
    "\t\t\t#dataPasswords, #dataWebSQL, \\\n"
    "\t\t\t#enableTimedForget, #timedForgetHour, \\\n"
    "\t\t\t#timedForgetMinute, #timedForgetTime, \\\n"
    "\t\t\t#setForgetTime\").change(function() {\n"
    "\t            forgetitoptions.forget_save_options();\n"
    "\t        });\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# The previously-anonymous change callback is given a name and referenced
# by identifier instead of being inlined -- a rule keyed on the literal
# ".change(function() {" pattern next to the #setForgetTime selector would
# miss this. Same exact vulnerability: #setForgetTime is still included in
# the generic, unvalidated bulk-save selector list.
RENAMED_BLOCK = (
    "\t        //Save settings as they are changed.\t\n"
    "\t        function saveAllSettings() {\n"
    "\t            forgetitoptions.forget_save_options();\n"
    "\t        }\n"
    "\t        $(\"#enableConfirmData, \\\n"
    "\t\t\t#clearDataFrom, \\\n"
    "\t\t\t#dataAppCache, #dataCache, \\\n"
    "\t\t\t#dataCookies, #dataDownloads, \\\n"
    "\t\t\t#dataFileSystems, #dataFormData, \\\n"
    "\t\t\t#dataHistory, #dataIndexedDB, \\\n"
    "\t\t\t#dataLocalStorage, #dataPluginData, \\\n"
    "\t\t\t#dataPasswords, #dataWebSQL, \\\n"
    "\t\t\t#enableTimedForget, #timedForgetHour, \\\n"
    "\t\t\t#timedForgetMinute, #timedForgetTime, \\\n"
    "\t\t\t#setForgetTime\").change(saveAllSettings);\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
assert renamed_source != original
assert "function saveAllSettings()" in renamed_source
assert '.change(saveAllSettings);' in renamed_source
assert "#setForgetTime" in renamed_source
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: equivalent API-call formatting -- the selector list is
# built as an array + .join(", ") instead of a single backslash-continued
# string literal. Same exact vulnerability (#setForgetTime still included,
# still no value validation), no renaming.
STRUCTURAL_BLOCK = (
    "\t        //Save settings as they are changed.\t\n"
    "\t        var settingsSelectors = [\n"
    "\t            \"#enableConfirmData\", \"#clearDataFrom\",\n"
    "\t            \"#dataAppCache\", \"#dataCache\",\n"
    "\t            \"#dataCookies\", \"#dataDownloads\",\n"
    "\t            \"#dataFileSystems\", \"#dataFormData\",\n"
    "\t            \"#dataHistory\", \"#dataIndexedDB\",\n"
    "\t            \"#dataLocalStorage\", \"#dataPluginData\",\n"
    "\t            \"#dataPasswords\", \"#dataWebSQL\",\n"
    "\t            \"#enableTimedForget\", \"#timedForgetHour\",\n"
    "\t            \"#timedForgetMinute\", \"#timedForgetTime\",\n"
    "\t            \"#setForgetTime\"\n"
    "\t        ];\n"
    "\t        $(settingsSelectors.join(\", \")).change(function() {\n"
    "\t            forgetitoptions.forget_save_options();\n"
    "\t        });\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "settingsSelectors.join" in structural_source
assert '"#setForgetTime"' in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (#setForgetTime removed from the
# generic unvalidated selector list; a value below 1 can never be saved)
# but via Math.max() clamping that always saves after normalizing the
# value, instead of the real patch's conditional skip-save-if-invalid
# approach -- materially different logic, not byte-identical to the
# known fix.
SAFE_BLOCK = (
    "\t        //Save settings as they are changed.\t\n"
    "\t        $('#setForgetTime').change(function() {\n"
    "\t            var minutes = parseInt(document.getElementById('setForgetTime').value, 10);\n"
    "\t            document.getElementById('setForgetTime').value = Math.max(1, minutes || 0);\n"
    "\t            forgetitoptions.forget_save_options();\n"
    "\t        });\n"
    "\t        $(\"#enableConfirmData, \\\n"
    "\t\t\t#clearDataFrom, \\\n"
    "\t\t\t#dataAppCache, #dataCache, \\\n"
    "\t\t\t#dataCookies, #dataDownloads, \\\n"
    "\t\t\t#dataFileSystems, #dataFormData, \\\n"
    "\t\t\t#dataHistory, #dataIndexedDB, \\\n"
    "\t\t\t#dataLocalStorage, #dataPluginData, \\\n"
    "\t\t\t#dataPasswords, #dataWebSQL, \\\n"
    "\t\t\t#enableTimedForget, #timedForgetHour, \\\n"
    "\t\t\t#timedForgetMinute, #timedForgetTime\").change(function() {\n"
    "\t            forgetitoptions.forget_save_options();\n"
    "\t        });\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "Math.max(1, minutes || 0)" in safe_source
# #setForgetTime must no longer appear in the generic bulk selector list
generic_selector_section = safe_source.split("$(\"#enableConfirmData")[1].split(").change")[0]
assert "#setForgetTime" not in generic_selector_section
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a change handler for a
# different field, the same superficial shape (.change(function() {
# forgetitoptions.forget_save_options(); }) with no value validation), but
# the field is a freeform text label that never drives a timer/loop
# interval, so accepting any value carries no denial-of-service risk.
BENIGN_ADDITION = (
    "\t        $('#customNoteLabel').change(function() {\n"
    "\t            // Freeform label text has no effect on any timer or loop\n"
    "\t            // interval, unlike #setForgetTime, so accepting any value\n"
    "\t            // here carries no denial-of-service risk.\n"
    "\t            forgetitoptions.forget_save_options();\n"
    "\t        });\n"
    "\n"
)
anchor = "\t        $('#setForgetTime').change(function() {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION + anchor, 1)
assert benign_source != safe_source
assert "customNoteLabel" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)

print("Wrote 4 new samples for CASE-0023.")
