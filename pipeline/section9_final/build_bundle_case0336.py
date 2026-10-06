r"""
Section 9 ground-truth test bundle: CASE-0336
(yogeshojha/rengine, web/reNgine/common_func.py get_cms_details,
CVE-2022-1813, CWE-78 OS command injection).

Core vulnerable mechanism: `get_cms_details(url)` builds a shell command by
string formatting, `'python3 /usr/src/github/CMSeeK/cmseek.py -u {} ...'.format(url)`,
and runs it with `os.system`. `url` is the scan target entered by the user, so
a value like `http://x.test/;touch /tmp/pwned;#` ends the CMSeeK command
and runs arbitrary shell commands in the reNgine worker (remote command
execution by any authenticated user who can add a target). The upstream fix
builds an argument list and runs it with `subprocess.Popen(argv)` (no shell).

Sibling sites: none in this function; other tool invocations elsewhere in
the project were handled separately.

Verification (REAL /bin/sh and subprocess execution): the full file is
executed with stand-ins for the Django/DRF imports, and `get_cms_details`
is called with a fake `python3` first on PATH that logs its arguments; the URL
is `http://x.test/;touch <marker>;#`. Vulnerable variants create the marker
file (the injected command ran) while the logged CMSeeK invocation is cut at
the `;`; patched/safe create no marker and pass the whole URL as the single
argument after `-u`. A plain URL reaches the fake CMSeeK with `-u <url>` in
every file.

Every variant is the FULL real file; `get_cms_details` is called by name from
the scan tasks.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0336"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


def func_span(text):
    a = text.index("def get_cms_details(url):\n")
    body = text.index("\n", a) + 1
    m = re.search(r"^\S", text[body:], re.M)
    return text[a:body + m.start()] if m else text[a:]


func = func_span(original)
assert func.count("os.system(cms_detector_command)") == 1

# --- Variant 1: renamed vulnerable variant (locals renamed inside get_cms_details; dict keys stay) ---
f1 = func
for old, new in [("cms_detector_command", "detector_cmd"), ("response", "outcome"), ("parsed_url", "parsed"),
                 ("domain_name", "host"), ("find_dir", "result_dir_name"), ("cms_dir_path", "result_dir"),
                 ("cms_json_path", "json_file"), ("cms_file_content", "detected")]:
    f1 = re.sub(r"(?<![\w.'\"])%s(?![\w'\"])" % old, new, f1)
assert "outcome['status']" in f1 and "detected.get('cms_id')" in f1
v1 = original.replace(func, f1)
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (command string built by a helper, still shell-run) ---
CMD = "    cms_detector_command = 'python3 /usr/src/github/CMSeeK/cmseek.py -u {} --random-agent --batch --follow-redirect'.format(url)\n"
f2 = swap(func, CMD, "    cms_detector_command = _cmseek_command(url)\n")
helper = ("def _cmseek_command(url):\n"
          "    return 'python3 /usr/src/github/CMSeeK/cmseek.py -u {} --random-agent --batch --follow-redirect'.format(url)\n\n\n")
v2 = original.replace(func, helper + f2)
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the argv list is built by a helper) ---
pfunc = func_span(patched)
ARGV = '''    cms_detector_command = 'python3 /usr/src/github/CMSeeK/cmseek.py --random-agent --batch --follow-redirect'
    subprocess_splitted_command = cms_detector_command.split()
    subprocess_splitted_command.append('-u')
    subprocess_splitted_command.append(url)
    process = subprocess.Popen(subprocess_splitted_command)
'''
pf3 = swap(pfunc, ARGV, "    process = subprocess.Popen(_cmseek_argv(url))\n")
helper3 = '''def _cmseek_argv(url):
    argv = 'python3 /usr/src/github/CMSeeK/cmseek.py --random-agent --batch --follow-redirect'.split()
    argv.extend(['-u', url])
    return argv


'''
v3 = patched.replace(pfunc, helper3 + pf3)
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''import os


def refresh_cms_signatures():
    """Update the CMS signature database: the command line is a constant, no user input reaches the shell."""
    command = 'python3 /usr/src/github/CMSeeK/update_signatures.py --quiet'
    os.system(command)
    return True
''')
