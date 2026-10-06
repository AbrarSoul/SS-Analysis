"""
Section 9 ground-truth test bundle: CASE-0161
(fail2ban/fail2ban, server/action.py Action.replaceTag, CVE-2012-5642,
NVD-CWE-noinfo; in substance OS command injection).

Core vulnerable mechanism: `replaceTag(query, aInfo)` substitutes every
`<tag>` in an action command with `str(aInfo[tag])`, and `executeCmd` runs
the result with `os.system` (a shell). `aInfo` includes `matches`, the log
lines that triggered the ban, which an attacker controls (for example through
a failed login username). Shell metacharacters in it (`;`, `|`, backticks,
`$(...)`) are therefore interpreted when the action uses `<matches>`, for
example `echo <matches>`, giving command execution as fail2ban's user
(usually root). The upstream fix backslash-escapes a fixed set of characters
in the `matches` value via a new `escapeTag` helper.

Measured caveat, kept in the manifest notes: upstream's patched replaceTag
calls a bare `escapeTag(value)`, but `escapeTag` is defined in the CLASS body,
so the name is not visible inside the function (Python looks it up in module
globals) and every substitution of `matches` raises NameError; it also uses
`dict.iteritems`, so it only runs on Python 2. The safe variant uses
`Action.escapeTag` and `for tag in aInfo`, which are valid on Python 2 and 3.

Sibling sites: replaceTag is the only substitution routine; every action
command (ban, unban, check, start, stop) goes through it.

Every variant is the FULL real file (Python 2 syntax, tab-indented).
replaceTag is a staticmethod called as Action.replaceTag by other methods, so
the renamed variant keeps the name and renames parameters and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0161"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

BODY = '''\tdef replaceTag(query, aInfo):
\t\t""" Replace tags in query
\t\t"""
\t\tstring = query
\t\tfor tag in aInfo:
\t\t\tstring = string.replace('<' + tag + '>', str(aInfo[tag]))
\t\t# New line
\t\tstring = string.replace("<br>", '\\n')
\t\treturn string
\treplaceTag = staticmethod(replaceTag)
'''
assert original.count(BODY) == 1
IMPORT = "import logging, os\n"
assert original.count(IMPORT) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BODY, '''\tdef replaceTag(query, aInfo):
\t\t""" Replace tags in query
\t\t"""
\t\tcommand = query
\t\tfor name in aInfo:
\t\t\tcommand = command.replace('<' + name + '>', str(aInfo[name]))
\t\t# New line
\t\tcommand = command.replace("<br>", '\\n')
\t\treturn command
\treplaceTag = staticmethod(replaceTag)
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BODY, '''\tdef replaceTag(query, aInfo):
\t\t""" Replace tags in query
\t\t"""
\t\tstring = query
\t\tpairs = [('<' + tag + '>', str(aInfo[tag])) for tag in aInfo]
\t\tfor placeholder, value in pairs:
\t\t\tstring = string.replace(placeholder, value)
\t\t# New line
\t\tstring = string.replace("<br>", '\\n')
\t\treturn string
\treplaceTag = staticmethod(replaceTag)
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# `matches` is escaped by backslash-escaping EVERY character outside a small
# safe set (letters, digits and _@%+=:,./-), so quotes, spaces, `!` and
# tabs are covered as well; upstream escapes a fixed list of metacharacters.
v3 = swap(original, BODY, '''\tdef escapeTag(tag):
\t\treturn re.sub(r'([^A-Za-z0-9_@%+=:,./-])', r'\\\\\\1', tag)
\tescapeTag = staticmethod(escapeTag)

\t#@staticmethod
\tdef replaceTag(query, aInfo):
\t\t""" Replace tags in query
\t\t"""
\t\tstring = query
\t\tfor tag in aInfo:
\t\t\tvalue = str(aInfo[tag])
\t\t\tif tag == 'matches':
\t\t\t\t# log content is out of our control: never let it reach the shell raw
\t\t\t\tvalue = Action.escapeTag(value)
\t\t\tstring = string.replace('<' + tag + '>', value)
\t\t# New line
\t\tstring = string.replace("<br>", '\\n')
\t\treturn string
\treplaceTag = staticmethod(replaceTag)
''')
v3 = swap(v3, IMPORT, "import logging, os, re\n")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import logging

logSys = logging.getLogger("fail2ban.benign")


def formatBanLogLine(template, aInfo):
\t"""Same <tag> substitution loop as Action.replaceTag, but the result is only
\twritten to the log (never handed to a shell), so shell metacharacters in the
\tmatched log lines are inert text."""
\tline = template
\tfor tag in aInfo:
\t\tline = line.replace('<' + tag + '>', str(aInfo[tag]))
\tlogSys.info(line)
\treturn line
'''
assert "never handed to a shell" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0161.")
