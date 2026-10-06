"""
Section 9 ground-truth test bundle: CASE-0145
(dimtion/Shaarlier, app/src/main/java/com/dimtion/shaarlier/TagsSource.java
createTag, CVE-2015-10076, CWE-89 SQL injection).

Core vulnerable mechanism: `createTag` looks the tag up with a WHERE clause
built by string concatenation,
`TAGS_COLUMN_TAG + " = '" + tag.getValue() + "'"`, where the value is
user-typed tag text. A quote in the tag breaks the statement: the query runs
BEFORE the `try`, so the SQLException is not caught by `catch (Exception e)`
and propagates (measured against real SQLite: any tag such as `it's` crashes
createTag). A crafted value such as `zzz' OR '1'='1` matches every row (measured:
it returns another account's tag instead of creating the new one). The upstream fix binds the account id and value as `?` selection
arguments.

Sibling site: none. `getAllTags` and `deleteAllTags` take no user input, and
the account id is a numeric getter.

Every variant is the FULL real file with createTag replaced. createTag is a
package-visible public method called from other classes, so the renamed
variant renames the declaration and the parameters/locals only.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0145"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public Tag createTag(ShaarliAccount masterAccount, String value) {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
QUERY = '''        Cursor cursor = db.query(MySQLiteHelper.TABLE_TAGS, allColumns,
                MySQLiteHelper.TAGS_COLUMN_ID_ACCOUNT + " = " + tag.getMasterAccountId() + " AND " +
                        MySQLiteHelper.TAGS_COLUMN_TAG + " = '" + tag.getValue() + "'",
                null, null, null, null);
'''
assert original.count(HDR) == 1 and BLOCK.count(QUERY) == 1 and original.count("createTag") == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


def rename(text, pairs):
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
b = rename(BLOCK, (("createTag", "addTag"), ("masterAccount", "account"), ("value", "tagText"), ("tag", "newTag"),
                   ("values", "row"), ("cursor", "existing"), ("insertId", "newId"), ("e", "ex")))
assert "public Tag addTag(ShaarliAccount account, String tagText)" in b
assert "newTag.getMasterAccountId()" in b and "\" = '\" + newTag.getValue() + \"'\"" in b
assert "catch (Exception ex)" in b and "existing.close()" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(QUERY, '''        String where = MySQLiteHelper.TAGS_COLUMN_ID_ACCOUNT + " = " + tag.getMasterAccountId();
        where += " AND " + MySQLiteHelper.TAGS_COLUMN_TAG + " = '" + tag.getValue() + "'";
        Cursor cursor = db.query(MySQLiteHelper.TABLE_TAGS, allColumns, where, null, null, null, null);
''')
assert b != BLOCK and "where += " in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Bound with `?` placeholders like upstream (selection args), but through a
# named selection constant and an inline argument array instead of upstream's
# separate getTagArgs variable.
b = BLOCK.replace(QUERY, '''        final String selection = MySQLiteHelper.TAGS_COLUMN_ID_ACCOUNT + " = ? AND "
                + MySQLiteHelper.TAGS_COLUMN_TAG + " = ?";
        Cursor cursor = db.query(MySQLiteHelper.TABLE_TAGS, allColumns, selection,
                new String[]{Long.toString(tag.getMasterAccountId()), tag.getValue()}, null, null, null);
''')
safe_source = build(b)
assert "= '\" +" not in b and "new String[]{Long.toString(" in b
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

class TagCounter {
    private final SQLiteDatabase db;

    TagCounter(SQLiteDatabase db) {
        this.db = db;
    }

    /**
     * Same string-concatenated WHERE clause as a tag lookup, but the only
     * concatenated pieces are developer-fixed column names and a validated
     * numeric id; no user-supplied text ever enters the SQL.
     */
    int countForAccount(long accountId) {
        Cursor cursor = db.query("tags", new String[]{"_id"},
                "id_account" + " = " + Long.valueOf(accountId), null, null, null, null);
        try {
            return cursor.getCount();
        } finally {
            cursor.close();
        }
    }
}
'''
assert "Long.valueOf(accountId)" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0145.")
