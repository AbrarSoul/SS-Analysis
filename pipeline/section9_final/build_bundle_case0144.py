"""
Section 9 ground-truth test bundle: CASE-0144
(dgtlmoon/changedetection.io, changedetectionio/blueprint/rss/tag.py
construct_tag_routes, CVE-2026-29038, CWE-79 reflected cross-site scripting).

Core vulnerable mechanism: the route `/tag/<string:tag_uuid>` accepts any
slash-free text as `tag_uuid`, and when no such tag exists the view returns
`f"Tag with UUID {tag_uuid} not found", 404` -- a plain str, which Flask
serves as text/html, so the URL segment is reflected unescaped (measured with
real Flask 3.1.3: `/rss/tag/%3Cimg%20src%3Dx%20onerror%3D...%3E` comes back as
a live <img onerror> in a text/html 404). A payload cannot contain `/`
(the converter stops there), so `<script>..</script>` does not fit but an
event-handler tag does. The upstream fix changes the converter to
`<uuid_str:tag_uuid>`, so a non-UUID segment never reaches the view.

Every variant is the FULL real file (the whole construct_tag_routes factory).
The view `rss_tag_feed` is registered by decorator and never called by name,
so it can be renamed; `tag_uuid` is also the URL variable, so the renamed
variant changes the route placeholder together with the parameter.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0144"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

ROUTE = '''    @rss_blueprint.route("/tag/<string:tag_uuid>", methods=['GET'])\n'''
NOTFOUND = '''        tag = datastore.data['settings']['application'].get('tags', {}).get(tag_uuid)
        if not tag:
            return f"Tag with UUID {tag_uuid} not found", 404
'''
assert original.count(ROUTE) == 1 and original.count(NOTFOUND) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = original.replace("tag_uuid", "tag_id").replace("rss_tag_feed", "tag_rss_feed").replace("tag_title", "feed_label")
v1 = swap(v1, "        tag = datastore.", "        tag_entry = datastore.")
v1 = swap(v1, "        if not tag:\n", "        if not tag_entry:\n")
v1 = swap(v1, "feed_label = tag.get('title', 'Unknown Tag')", "feed_label = tag_entry.get('title', 'Unknown Tag')")
assert '"/tag/<string:tag_id>"' in v1 and "def tag_rss_feed(tag_id):" in v1
assert 'f"Tag with UUID {tag_id} not found", 404' in v1 and "if tag_id not in watch.get('tags', [])" in v1
assert "tag_uuid" not in v1 and "tag.get(" not in v1
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, NOTFOUND, '''        tag = datastore.data['settings']['application'].get('tags', {}).get(tag_uuid)
        if tag is None or not tag:
            message = "Tag with UUID " + tag_uuid + " not found"
            return message, 404
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The route still takes any string, but the reflected value is HTML-escaped
# with markupsafe; upstream instead restricts the URL converter to UUIDs.
v3 = swap(original, NOTFOUND, '''        tag = datastore.data['settings']['application'].get('tags', {}).get(tag_uuid)
        if not tag:
            from markupsafe import escape
            return f"Tag with UUID {escape(tag_uuid)} not found", 404
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''def construct_lookup_routes(blueprint, datastore):
    """Same "unknown id -> 404 that mentions the id" route shape as a tag feed."""

    @blueprint.route("/lookup/<string:item_id>", methods=['GET'])
    def lookup_item(item_id):
        item = datastore.data.get('items', {}).get(item_id)
        if not item:
            # A dict is serialized by Flask as application/json, never as
            # HTML, so the reflected id cannot be interpreted as markup.
            return {"error": f"Item {item_id} not found"}, 404
        return {"id": item_id, "title": item.get('title')}
'''
assert "application/json" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0144.")
