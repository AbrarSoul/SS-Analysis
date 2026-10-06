"""
Section 9 ground-truth test bundle: CASE-0180
(jaspernbrouwer/powerline-gitstatus, powerline_gitstatus/segments.py
GitStatusSegment.get_base_command, CVE-2022-42906, CWE-77 command injection).
This case is the replacement added by top-up 12 after mirrormanager2 was
excluded.

Core vulnerable mechanism: the segment runs `git status ...` in whatever
directory the shell prompt is in, building the command as
`['git', '-C', cwd]` or `['git', '--git-dir=..', '--work-tree=..']`. Git reads
the repository's own config, and a repo can set `core.fsmonitor` to an
arbitrary command that git then EXECUTES on `git status`. Simply `cd`-ing into
a malicious repository therefore runs attacker code when the prompt renders.
The upstream fix adds `-c core.fsmonitor=` (empty) at both return sites.

Measured with the real git 2.54: with `core.fsmonitor=<script>` in
.git/config, the vulnerable command runs the script (marker file created);
with `-c core.fsmonitor=` or `-c core.fsmonitor=false` it does not.

Sibling sites: both `return` statements of get_base_command build a git
command (the -C branch and the git-dir branch), and both are fixed together.

Every variant is the FULL real file. get_base_command is called by name from
`__call__`, so the renamed variant keeps the name and renames parameters and
locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0180"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

BODY = '''    def get_base_command(self, cwd, use_dash_c):
        if use_dash_c:
            return ['git', '-C', cwd]

        while cwd and cwd != os.sep:
            gitdir = os.path.join(cwd, '.git')

            if os.path.isdir(gitdir):
                return ['git', '--git-dir=%s' % gitdir, '--work-tree=%s' % cwd]

            cwd = os.path.dirname(cwd)

        return None
'''
assert original.count(BODY) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
b = BODY
for old, new in (("cwd", "start_dir"), ("use_dash_c", "dash_c"), ("gitdir", "git_dir")):
    b = re.sub(r"(?<![.\w$'])%s(?![\w$'])" % old, new, b)
assert "['git', '-C', start_dir]" in b and "'--work-tree=%s' % start_dir" in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(swap(original, BODY, b))

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BODY, '''    def find_git_dir(self, cwd):
        while cwd and cwd != os.sep:
            gitdir = os.path.join(cwd, '.git')

            if os.path.isdir(gitdir):
                return (gitdir, cwd)

            cwd = os.path.dirname(cwd)

        return None

    def get_base_command(self, cwd, use_dash_c):
        if use_dash_c:
            return ['git', '-C', cwd]

        found = self.find_git_dir(cwd)
        if found is None:
            return None

        return ['git', '--git-dir=%s' % found[0], '--work-tree=%s' % found[1]]
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# A shared constant carries the neutralising config for BOTH command shapes:
# fsmonitor is switched off with the boolean value `false` (upstream sets it to
# the empty string).
v3 = swap(original, BODY, '''    SAFE_GIT_CONFIG = ['-c', 'core.fsmonitor=false']

    def get_base_command(self, cwd, use_dash_c):
        if use_dash_c:
            return ['git'] + self.SAFE_GIT_CONFIG + ['-C', cwd]

        while cwd and cwd != os.sep:
            gitdir = os.path.join(cwd, '.git')

            if os.path.isdir(gitdir):
                return ['git'] + self.SAFE_GIT_CONFIG + ['--git-dir=%s' % gitdir, '--work-tree=%s' % cwd]

            cwd = os.path.dirname(cwd)

        return None
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''from subprocess import PIPE, Popen


def git_version():
    """Same Popen(['git', ...]) call shape as the status segment, but the
    command is a fixed argument list that does not touch any repository, so no
    repository-supplied configuration (such as core.fsmonitor) is ever read."""
    proc = Popen(['git', '--version'], stdout=PIPE, stderr=PIPE)
    return proc.communicate()[0].decode('utf-8').strip()
'''
assert "does not touch any repository" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0180.")
