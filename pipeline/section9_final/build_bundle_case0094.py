"""
Section 9 ground-truth test bundle: CASE-0094
(ajenti/ajenti, CVE-2019-25066, CWE-78/CWE-269 OS command injection).

Core vulnerable mechanism: OSAuthenticationProvider.authenticate() builds a
shell command by string-formatting the login name straight into it --
`pexpect.spawn('/bin/sh', ['-c', '/bin/su -c "/bin/echo SUCCESS" - %s' % username])`.
A username such as `x; touch /tmp/pwned` is interpreted by /bin/sh, giving
command execution (as the Ajenti process user, typically root) BEFORE any
password is checked. The upstream fix wraps the username in shlex.quote()
(pipes.quote on Python 2).

`authenticate` is an interface method called polymorphically through
AuthenticationService, so it cannot be renamed; the renamed variant renames
the parameters and locals only.

Every variant is the FULL real file with the method replaced.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0094"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.py").read_text().splitlines()) + "\n"

BLOCK = '''    def authenticate(self, username, password):
        child = None
        try:
            child = pexpect.spawn('/bin/sh', ['-c', '/bin/su -c "/bin/echo SUCCESS" - %s' % username], timeout=5)
            child.expect('.*:')
            child.sendline(password)
            result = child.expect(['su: .*', 'SUCCESS'])
        except Exception as err:
            if child and child.isalive():
                child.close()
            logging.error('Error checking password: %s', err)
            return False
        if result == 0:
            return False
        else:
            return True
'''
assert original.count(BLOCK) == 1


def build(new_block):
    assert new_block != BLOCK
    return original.replace(BLOCK, new_block)


# --- Variant 1: renamed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_01.py").write_text(build('''    def authenticate(self, login_name, secret):
        proc = None
        try:
            proc = pexpect.spawn('/bin/sh', ['-c', '/bin/su -c "/bin/echo SUCCESS" - %s' % login_name], timeout=5)
            proc.expect('.*:')
            proc.sendline(secret)
            outcome = proc.expect(['su: .*', 'SUCCESS'])
        except Exception as error:
            if proc and proc.isalive():
                proc.close()
            logging.error('Error checking password: %s', error)
            return False
        if outcome == 0:
            return False
        else:
            return True
'''))

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.py").write_text(build('''    def authenticate(self, username, password):
        child = None
        command = '/bin/su -c "/bin/echo SUCCESS" - {0}'.format(username)
        try:
            child = pexpect.spawn('/bin/sh', ['-c', command], timeout=5)
            child.expect('.*:')
            child.sendline(password)
            result = child.expect(['su: .*', 'SUCCESS'])
        except Exception as err:
            if child and child.isalive():
                child.close()
            logging.error('Error checking password: %s', err)
            return False
        return result != 0
'''))

# --- Variant 3: transformed safe variant ---
# No shell at all: su is spawned directly with an argument vector, and the
# username is first restricted to a conservative account-name grammar (which
# also rules out an option-like name starting with '-'). Different from
# upstream's shlex.quote() of a string still passed to /bin/sh -c.
safe = build('''    def authenticate(self, username, password):
        child = None
        if not re.match(r'^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$', username or ''):
            return False
        try:
            child = pexpect.spawn('/bin/su', ['-c', '/bin/echo SUCCESS', '-', username], timeout=5)
            child.expect('.*:')
            child.sendline(password)
            result = child.expect(['su: .*', 'SUCCESS'])
        except Exception as err:
            if child and child.isalive():
                child.close()
            logging.error('Error checking password: %s', err)
            return False
        if result == 0:
            return False
        else:
            return True
''')
assert original.count("import pwd\n") == 1
safe = safe.replace("import pwd\n", "import pwd\nimport re\n", 1)
(CASE_DIR / "variant_safe_01.py").write_text(safe)

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.py").write_text('''import os
import subprocess


def current_user_name():
    """Same '/bin/sh -c "<cmd> %s" % value' shape, but the interpolated value
    is an integer returned by the operating system (os.getuid(), formatted
    with %d), never text supplied by a remote user, so no shell
    metacharacters can be injected."""
    command = '/usr/bin/id -nu %d' % os.getuid()
    return subprocess.check_output(['/bin/sh', '-c', command]).decode().strip()
''')
print("Wrote 4 new samples for CASE-0094.")
