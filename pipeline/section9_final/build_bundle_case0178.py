"""
Section 9 ground-truth test bundle: CASE-0178
(janeczku/calibre-web, cps/shelf.py create_edit_shelf, CVE-2021-4171,
CWE-840 business logic error).

Core vulnerable mechanism: `create_edit_shelf` applies the submitted
visibility to the ORM object FIRST (`shelf.is_public = 1 if ... else 0`), then
calls `check_shelf_is_unique`, which reads `shelf.is_public` and runs a query
(autoflush writes the dirty object into the session's transaction). When the
uniqueness check FAILS the view only flashes an error, but the changed
`is_public` stays pending on the session object and is persisted by the next
commit made through the same session, so a shelf can be made public (or
private) even though the request was rejected, and the uniqueness rule is
evaluated on the unsaved, attacker-chosen state. The upstream fix keeps the
submitted value in a local `is_public`, passes it to the check, and assigns it
to the shelf only after the check passed.

Measured with real SQLAlchemy 2.0 (the function's own code run over an
in-memory database): a private shelf edited to public with a title that already
exists as a public shelf is rejected, yet after an unrelated `session.commit()`
the shelf is public in the database.

Sibling sites: `check_shelf_is_unique` is only called from this function, so it
is the only consumer of the pre-assigned state.

Every variant is the FULL real file. create_edit_shelf is called by name from
`create_shelf` and `edit_shelf`, so the renamed variant keeps the name and
renames its locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0178"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

s = original.index("def create_edit_shelf(shelf, page_title, page, shelf_id=False):\n")
e = original.index("\n\ndef check_shelf_is_unique(", s)
BLOCK = original[s:e]
APPLY = '''        shelf.is_public = 1 if to_save.get("is_public") else 0
        if config.config_kobo_sync:
            shelf.kobo_sync = True if to_save.get("kobo_sync") else False
        shelf_title = to_save.get("title", "")
        if check_shelf_is_unique(shelf, shelf_title, shelf_id):
            shelf.name = shelf_title
'''
assert BLOCK.count(APPLY) == 1
CHECK_DEF = "def check_shelf_is_unique(shelf, title, shelf_id=False):\n"
assert original.count(CHECK_DEF) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
parts = re.split(r'("(?:[^"\\]|\\.)*")', BLOCK)
for i in range(0, len(parts), 2):
    for old, new in (("to_save", "form_data"), ("shelf_title", "new_title"), ("shelf_action", "action_word"),
                     ("flash_text", "notice"), ("ex", "problem")):
        parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
b = "".join(parts)
assert 'form_data = request.form.to_dict()' in b and "check_shelf_is_unique(shelf, new_title, shelf_id)" in b
assert "except (OperationalError, InvalidRequestError) as problem:" in b and "log.debug_or_exception(problem)" in b
assert 'title=new_title' in b and "shelf.is_public = 1 if form_data.get(\"is_public\") else 0" in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + b + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, APPLY, '''        apply_shelf_form(shelf, to_save)
        shelf_title = to_save.get("title", "")
        if check_shelf_is_unique(shelf, shelf_title, shelf_id):
            shelf.name = shelf_title
''')
v2 = swap(v2, "# if shelf ID is set, we are editing a shelf\ndef create_edit_shelf(", '''def apply_shelf_form(shelf, to_save):
    shelf.is_public = 1 if to_save.get("is_public") else 0
    if config.config_kobo_sync:
        shelf.kobo_sync = True if to_save.get("kobo_sync") else False


# if shelf ID is set, we are editing a shelf
def create_edit_shelf(''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The submitted visibility is validated FIRST through an optional argument of
# check_shelf_is_unique and only then written to the shelf (and the check is
# run without autoflush, so nothing pending can leak into the transaction);
# upstream changes the check's signature to a required is_public argument.
v3 = swap(original, APPLY, '''        is_public = 1 if to_save.get("is_public") else 0
        if config.config_kobo_sync:
            shelf.kobo_sync = True if to_save.get("kobo_sync") else False
        shelf_title = to_save.get("title", "")
        with ub.session.no_autoflush:
            title_is_free = check_shelf_is_unique(shelf, shelf_title, shelf_id, is_public=is_public)
        if title_is_free:
            shelf.is_public = is_public
            shelf.name = shelf_title
''')
v3 = swap(v3, CHECK_DEF, "def check_shelf_is_unique(shelf, title, shelf_id=False, is_public=None):\n")
v3 = swap(v3, "    if shelf.is_public == 1:\n        is_shelf_name_unique", "    if (shelf.is_public if is_public is None else is_public) == 1:\n        is_shelf_name_unique")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''def rename_shelf(session, shelf, new_title, is_title_free):
    """Same assign-then-validate ordering as the shelf editor, but the object
    is only ever changed in memory and the change is rolled back when
    validation fails, and the assigned field is a display title, not the
    shelf's visibility, so a rejected edit cannot leave a privilege change
    pending on the session."""
    old_title = shelf.name
    shelf.name = new_title
    if not is_title_free(shelf):
        shelf.name = old_title
        session.rollback()
        return False
    session.commit()
    return True
'''
assert "rolled back" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0178.")
