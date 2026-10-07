"""
Section 9 ground-truth test bundle: CASE-0219
(metersphere/metersphere, framework/gateway/.../UserLoginService.java
checkUserPassword, CVE-2023-32699, CWE-770 allocation of resources without
limits or throttling).

Core vulnerable mechanism: the login path calls `checkUserPassword(userId,
password)`, which rejects blank values but places no bound on their length and
then runs `CodingUtil.md5(password)` and a database query built from
`userId` and the hash. An unauthenticated client can post a multi-megabyte
userId / password to the login endpoint, forcing the gateway to buffer, hash and
send them to the database for every attempt. The upstream fix rejects a userId
longer than 64 characters and a password longer than 30 characters before the
hash and the query.

Measured caveat, kept in the manifest notes: the 30-character password cap
also rejects legitimate longer passwords, and the two new Translator keys
(`user_id_length_too_long`, `password_length_too_long`) live in resource files
that are not part of this file. The safe variant uses a 64 / 128 limit and the
same keys.

Sibling sites: `checkUserPassword` is the only path here that hashes a
caller-supplied password (`login` at the top calls it; line ~479 hashes the
constant default password "metersphere"), so there is no second unbounded site.

Verification: the method is extracted verbatim from each full file into a
class compiled with javac against stand-in StringUtils, MSException,
Translator, CodingUtil (real MessageDigest MD5, counting the bytes hashed),
UserExample and userMapper. A 5,000,000-character password and 100,000-character
userId are submitted, followed by a normal login.

Every variant is the FULL real file. checkUserPassword is public and called from
`login`, so its name and signature are kept; the renamed variant renames the
parameters and the local.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0219"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

s = original.index("    public boolean checkUserPassword(String userId, String password) {")
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
assert original.count(BLOCK) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


V1 = '''    public boolean checkUserPassword(String userId, String password) {
        String loginName = userId;
        String secret = password;
        if (StringUtils.isBlank(loginName)) {
            MSException.throwException(Translator.get("user_name_is_null"));
        }
        if (StringUtils.isBlank(secret)) {
            MSException.throwException(Translator.get("password_is_null"));
        }
        UserExample lookup = new UserExample();
        lookup.createCriteria().andIdEqualTo(loginName).andPasswordEqualTo(CodingUtil.md5(secret));
        return userMapper.countByExample(lookup) > 0;
    }
'''
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(V1))

V2 = '''    private static void requireNotBlank(String value, String messageKey) {
        if (StringUtils.isBlank(value)) {
            MSException.throwException(Translator.get(messageKey));
        }
    }

    public boolean checkUserPassword(String userId, String password) {
        requireNotBlank(userId, "user_name_is_null");
        requireNotBlank(password, "password_is_null");
        UserExample example = new UserExample();
        example.createCriteria().andIdEqualTo(userId).andPasswordEqualTo(CodingUtil.md5(password));
        return userMapper.countByExample(example) > 0;
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(V2))

V3 = '''    private static final int MAX_USER_ID_LENGTH = 64;
    private static final int MAX_PASSWORD_LENGTH = 128;

    public boolean checkUserPassword(String userId, String password) {
        if (StringUtils.isBlank(userId)) {
            MSException.throwException(Translator.get("user_name_is_null"));
        }
        if (StringUtils.isBlank(password)) {
            MSException.throwException(Translator.get("password_is_null"));
        }
        if (userId.length() > MAX_USER_ID_LENGTH) {
            MSException.throwException(Translator.get("user_id_length_too_long"));
        }
        if (password.length() > MAX_PASSWORD_LENGTH) {
            MSException.throwException(Translator.get("password_length_too_long"));
        }
        UserExample example = new UserExample();
        example.createCriteria().andIdEqualTo(userId).andPasswordEqualTo(CodingUtil.md5(password));
        return userMapper.countByExample(example) > 0;
    }
'''
(CASE_DIR / "variant_safe_01.java").write_text(build(V3))

BENIGN = '''package io.metersphere.gateway.service;

/**
 * Standalone example of the same shape (blank check, then a length check on a
 * short, server-defined value) for a display-name field that is never hashed or
 * used in a query.
 */
public class DisplayNameCheck {

    public static boolean isAcceptable(String displayName) {
        if (displayName == null || displayName.trim().isEmpty()) {
            return false;
        }
        return displayName.length() <= 64;
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN)
