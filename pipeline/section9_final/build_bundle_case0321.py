r"""
Section 9 ground-truth test bundle: CASE-0321
(viakondratiuk/cash-machine, machine.py get_card and block_card,
CVE-2015-10069, CWE-89 SQL injection).

Core vulnerable mechanism: `get_card(request, cc_number)` builds its lookup
with Python string formatting,
`"select * from cards where cc_number = '%s'" % cc_number.replace('-', '')`,
and executes the string. `cc_number` is the value the user types on the
start page, so a card number such as `x' OR '1'='1` rewrites the WHERE clause
and returns an arbitrary card record (authentication bypass of the "enter
your card" step). The same file's `block_card` formats `card['id']` into an
UPDATE with `%s`; the upstream fix moves both statements to sqlite
`?` placeholders.

Sibling sites: `block_card` is the second string-formatted statement in the
patch; the other statements in the file (`update_failed_attempts`,
`save_balance_check`, `save_withdraw`) already use placeholders.

Verification (REAL sqlite3): `get_card` and `block_card` (plus any helper
a variant adds) are sliced from each full file and exec'd against an
in-memory sqlite3 database with a `cards` table of three cards (a request
stand-in exposes `.db` and `.session`). Probes: a legitimate dashed card
number, the payload `x' OR '1'='1`, and `block_card` with a session card id of
`1 OR 1=1`. Vulnerable variants return a card for the payload and block ALL
three cards; patched/safe return None and block none; the legitimate lookup
works in every file.

Every variant is the FULL real file; both functions keep their names and
signatures because the Pyramid views call them.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0321"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


GET_Q = '''    q = "select * from cards where cc_number = '%s'" % cc_number.replace('-', '')
    row = request.db.execute(q).fetchone()
    if row is not None:
        return dict(
            id = row[0],
            cc_number = row[1],
            pin = row[2],
            failed_attempts = row[3],
            status = row[4],
            balance = row[5],
            cc_dashed = cc_number,
            valid_pin = False
        )
'''
BLOCK = '''    card = request.session['card']
    request.db.execute("update cards set status = 'blocked' where id = %s" % card['id'])
    request.db.commit()
'''
assert original.count(GET_Q) == 1 and original.count(BLOCK) == 1

# --- Variant 1: renamed vulnerable variant (locals renamed; the returned dict keys stay) ---
g1 = (GET_Q.replace("    q = ", "    lookup_sql = ").replace("execute(q)", "execute(lookup_sql)")
      .replace("    row = ", "    found = ").replace("if row is not None", "if found is not None"))
for i in range(6):
    g1 = g1.replace("= row[%d]" % i, "= found[%d]" % i)
assert "row" not in g1
b1 = BLOCK.replace("card = request.session", "session_card = request.session").replace("% card['id']", "% session_card['id']")
assert "session_card['id']" in b1
v1 = swap(swap(original, GET_Q, g1), BLOCK, b1)
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (statements built by helper functions, still formatted) ---
g2 = GET_Q.replace('''    q = "select * from cards where cc_number = '%s'" % cc_number.replace('-', '')\n''',
                   "    q = _card_lookup_sql(cc_number)\n")
b2 = BLOCK.replace('''request.db.execute("update cards set status = 'blocked' where id = %s" % card['id'])''',
                   "request.db.execute(_block_sql(card))")
helpers = '''def _card_lookup_sql(cc_number):
    return "select * from cards where cc_number = '%s'" % cc_number.replace('-', '')

def _block_sql(card):
    return "update cards set status = 'blocked' where id = %s" % card['id']

'''
v2 = swap(swap(original, GET_Q, g2), BLOCK, b2)
v2 = swap(v2, "def get_card(request, cc_number):\n", helpers + "def get_card(request, cc_number):\n")
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the statement text moves into module constants) ---
PG = '''    row = request.db.execute("select * from cards where cc_number = ?", (cc_number.replace('-', ''),)).fetchone()\n'''
PB = '''    request.db.execute("update cards set status = 'blocked' where id = ?", (card['id'],))\n'''
v3 = swap(patched, PG, "    row = request.db.execute(CARD_BY_NUMBER_SQL, (cc_number.replace('-', ''),)).fetchone()\n")
v3 = swap(v3, PB, "    request.db.execute(BLOCK_CARD_SQL, (card['id'],))\n")
v3 = swap(v3, "def get_card(request, cc_number):\n",
          "CARD_BY_NUMBER_SQL = \"select * from cards where cc_number = ?\"\nBLOCK_CARD_SQL = \"update cards set status = 'blocked' where id = ?\"\n\ndef get_card(request, cc_number):\n")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''import sqlite3

COUNTABLE_STATUSES = ('active', 'blocked', 'expired')


def count_cards_by_status(db, status):
    """Count cards in a status.

    The status is checked against a fixed allow-list before it is formatted
    into the statement, and the only value that ever reaches the SQL text is
    one of the three literals above, so the string formatting cannot carry
    user input.
    """
    if status not in COUNTABLE_STATUSES:
        raise ValueError('unknown status')
    return db.execute("select count(*) from cards where status = '%s'" % status).fetchone()[0]
''')
