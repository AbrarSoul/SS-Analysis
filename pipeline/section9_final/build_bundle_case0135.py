"""
Section 9 ground-truth test bundle: CASE-0135
(cloudexplorer-dev/cloudexplorer-lite, BaseUserServiceImpl.resetPwd,
CVE-2023-3423, CWE-521 weak password requirements).

Core vulnerable mechanism: `resetPwd(request, currentUser)` verifies the old
password and then stores `MD5Util.md5(request.getNewPassword())` with NO
password policy at all: a one-character password, or exactly the old
password, is accepted, so users (and an attacker who obtains a session) can
set trivially guessable credentials. The upstream fix adds (a) a rejection
when old and new are equal and (b) a complexity regex (8-30 characters, no
whitespace, upper + lower + digit + special).

Every variant is the FULL real file with resetPwd(request, currentUser)
replaced. It is an @Override of the service interface (the 1-argument
overload delegates to it), so the renamed variant renames parameters and
locals, not the method. Only one password-setting site exists in the file.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0135"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public boolean resetPwd(ResetPwdRequest request, UserDto currentUser) {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
OLDCHK = '''        if (!MD5Util.md5(request.getOldPassword()).equalsIgnoreCase(user.getPassword())) {
            throw new RuntimeException("旧密码错误");
        }
'''
SETPW = "        user.setPassword(MD5Util.md5(request.getNewPassword()));\n"
assert original.count(HDR) == 1 and BLOCK.count(OLDCHK) == 1 and BLOCK.count(SETPW) == 1
assert original.count("setPassword(") == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename_outside_strings(BLOCK, (("request", "req"), ("currentUser", "actor"), ("user", "account")))
assert "public boolean resetPwd(ResetPwdRequest req, UserDto actor) {" in b
assert "account.setPassword(MD5Util.md5(req.getNewPassword()));" in b and "this.getUserById(actor.getId())" in b
assert 'throw new RuntimeException("旧密码错误");' in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(OLDCHK, "        assertOldPasswordMatches(user, request.getOldPassword());\n")
helper = '''
    private void assertOldPasswordMatches(User user, String oldPassword) {
        if (!MD5Util.md5(oldPassword).equalsIgnoreCase(user.getPassword())) {
            throw new RuntimeException("旧密码错误");
        }
    }
'''
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# Policy enforced by an imperative character-class check (upstream: one
# regex); "new equals old" is decided by comparing the HASH of the new
# password with the stored hash (upstream compares the two request strings).
b = BLOCK.replace(OLDCHK, OLDCHK + '''        if (!meetsPasswordPolicy(request.getNewPassword())) {
            throw new RuntimeException("有效密码：8-30位，英文大小写字母+数字+特殊字符");
        }
        if (MD5Util.md5(request.getNewPassword()).equalsIgnoreCase(user.getPassword())) {
            throw new RuntimeException("新旧密码相同");
        }
''')
helper = '''
    private static boolean meetsPasswordPolicy(String password) {
        if (password == null || password.length() < 8 || password.length() > 30) {
            return false;
        }
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean special = false;
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            // same notion as the regex: ASCII \\s, plus the line terminators '.' does not match
            if (c == ' ' || (c >= '\\t' && c <= '\\r') || c == '\\u0085' || c == '\\u2028' || c == '\\u2029') {
                return false;
            }
            if (c >= 'A' && c <= 'Z') {
                upper = true;
            } else if (c >= 'a' && c <= 'z') {
                lower = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            } else {
                special = true;
            }
        }
        return upper && lower && digit && special;
    }
'''
safe_source = build(b, extra_after=helper)
assert "meetsPasswordPolicy(" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import com.fit2cloud.common.utils.MD5Util;

import java.security.SecureRandom;

public class TemporaryPasswords {

    private static final String ALPHABET =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*";
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Same "user.setPassword(MD5Util.md5(<new password>))" shape, but the new
     * password is NOT chosen by the requester: it is a fresh 16-character
     * value drawn from a SecureRandom over a 64-symbol alphabet (96 bits of
     * entropy), so no weak or reused password can be introduced here.
     */
    public String resetToTemporaryPassword(com.fit2cloud.base.entity.User user) {
        StringBuilder generated = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            generated.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        user.setPassword(MD5Util.md5(generated.toString()));
        return generated.toString();
    }
}
'''
assert "SecureRandom" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0135.")
