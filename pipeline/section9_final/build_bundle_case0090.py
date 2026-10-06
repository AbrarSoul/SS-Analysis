"""
Section 9 ground-truth test bundle: CASE-0090
(airbnb/knowledge-repo, CVE-2018-12104, CWE-79 stored XSS).

Core vulnerable mechanism: `post_comment()` stores the request-supplied
comment text verbatim (`comment.text = data['text']`) and the text is
later rendered into pages, so a comment containing `<script>` executes in
other users' browsers. The upstream fix wraps it in flask's `escape()`.

Note: the file has TWO functions named post_comment (the route, and a
later object_extractor that rebinds the name); the renamed variant
renames the route function and rewires `@post_comment.object_extractor`
to it, and renames the second definition so the module stays coherent.

Every variant is the FULL real file with the route function replaced.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0090"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.py").read_text().splitlines()) + "\n"

BLOCK = '''def post_comment():
    """ Post a comment underneath a post """

    path = request.args.get('path', '')
    comment_id = request.args.get('comment_id')
    data = request.get_json()

    post = (db_session.query(Post)
                      .filter(Post.path == path)
                      .first())

    if not post:
        raise Exception('Unable to find post')

    if comment_id:
        comment = (db_session.query(Comment)
                             .filter(Comment.id == comment_id)
                             .first())
    else:
        comment = Comment(post_id=post.id)

    comment.text = data['text']
    comment.user_id = current_user.id
    db_session.add(comment)
    db_session.commit()

    send_comment_email(path=path,
                       commenter=current_user.format_name,
                       comment_text=data['text'])
    return "OK"
'''
assert original.count(BLOCK) == 1
assert original.count("@post_comment.object_extractor\ndef post_comment():") == 1


def build(new_block, text=None):
    return (text or original).replace(BLOCK, new_block)


# --- Variant 1: renamed vulnerable variant ---
renamed = build('''def create_comment():
    """ Post a comment underneath a post """

    page_path = request.args.get('path', '')
    parent_id = request.args.get('comment_id')
    payload = request.get_json()

    target_post = (db_session.query(Post)
                             .filter(Post.path == page_path)
                             .first())

    if not target_post:
        raise Exception('Unable to find post')

    if parent_id:
        entry = (db_session.query(Comment)
                           .filter(Comment.id == parent_id)
                           .first())
    else:
        entry = Comment(post_id=target_post.id)

    entry.text = payload['text']
    entry.user_id = current_user.id
    db_session.add(entry)
    db_session.commit()

    send_comment_email(path=page_path,
                       commenter=current_user.format_name,
                       comment_text=payload['text'])
    return "OK"
''')
renamed = renamed.replace("@post_comment.object_extractor\ndef post_comment():",
                          "@create_comment.object_extractor\ndef comment_reference():")
assert "@create_comment.object_extractor" in renamed and "def post_comment" not in renamed
assert "@permissions.post_comment.require()" in renamed  # permission object name is not ours to rename
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(BLOCK.replace(
    "    comment.text = data['text']\n",
    "    submitted_text = data['text']\n    comment.text = submitted_text\n")))

# --- Variant 3: transformed safe variant ---
# stdlib html.escape (quote=True) applied to the stored text, instead of
# flask.escape as upstream does.
safe_block = BLOCK.replace("    comment.text = data['text']\n", "    comment.text = html.escape(data['text'], quote=True)\n")
safe = build(safe_block).replace("import logging\n", "import html\nimport logging\n", 1)
assert "import html\n" in safe and "html.escape(data['text'], quote=True)" in safe
(CASE_DIR / "variant_safe_01.py").write_text(safe)

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.py").write_text('''import re

_NOTE_TEXT = re.compile(r"[A-Za-z0-9 .,]{1,200}")


def save_audit_note(audit, data):
    """Same `record.text = data['text']` shape, but the text is first
    restricted to plain letters, digits, spaces and basic punctuation, so
    it can contain no HTML metacharacters and cannot carry markup."""
    text = data["text"]
    if not _NOTE_TEXT.fullmatch(text):
        raise ValueError("invalid note text")
    audit.text = text
    return audit
''')
print("Wrote 4 new samples for CASE-0090.")
