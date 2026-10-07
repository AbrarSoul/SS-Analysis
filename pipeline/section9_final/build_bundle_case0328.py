r"""
Section 9 ground-truth test bundle: CASE-0328
(wekan/wekan, server/publications/attachments.js attachmentsList,
CVE-2026-25562, CWE-203 observable discrepancy / information exposure).

Core vulnerable mechanism: the `attachmentsList` Meteor publication returns
`ReactiveCache.getAttachments({}, {...})`, an EMPTY selector, so every
logged-in (or even anonymous) subscriber receives the metadata of every
attachment on the server (file name, size, type, path, `meta.cardId` /
`meta.boardId`), including attachments on private boards the caller is not a
member of. The upstream fix computes the boards the user may see (public or
active membership), the non-archived cards on those boards, and restricts the
attachment selector to `meta.cardId` in those cards (empty result when there
are none).

Sibling sites: other publications in the module scope their selectors by
board membership; this one had no scoping.

Verification (REAL query engine): each full file is evaluated with node's
`vm` (imports removed, `Meteor.publish` captured, `this.userId`/`this.ready`
provided). A stand-in `ReactiveCache` runs `getBoards`, `getCards` and
`getAttachments` selectors, projections, sort and limit with the real
`mingo` MongoDB query library over an in-memory data set: private board B1
(member u1), private board B2 (member u2), public board B3, one card on each,
an archived card on B1, and one attachment per card. Subscribers: u1, a user
with no memberships (u3) and anonymous. Vulnerable variants publish all 4
attachments to everyone; patched/safe publish a1 (B1, member) and a3
(public) to u1, only a3 to u3 and anonymous.

Every variant is the FULL real file; the publication name `attachmentsList`
is the client API and stays.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0328"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant (publication parameter and local renamed; the `limit:` key stays) ---
v1 = swap(original, "Meteor.publish('attachmentsList', function(limit) {\n  const ret = ReactiveCache.getAttachments(",
          "Meteor.publish('attachmentsList', function(maxItems) {\n  const list = ReactiveCache.getAttachments(")
v1 = swap(v1, "      limit: limit,\n", "      limit: maxItems,\n")
v1 = swap(v1, "  ).cursor;\n  return ret;\n", "  ).cursor;\n  return list;\n")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (the query moved into a helper function) ---
BODY = original[original.index("  const ret = ReactiveCache.getAttachments("):original.index("  return ret;\n});\n")]
v2 = swap(original, "Meteor.publish('attachmentsList', function(limit) {\n" + BODY + "  return ret;\n});\n",
          "function allAttachments(limit) {\n" + BODY.replace("const ret =", "return") .rstrip("\n").rstrip(";").rstrip() + ";\n}\n\n"
          "Meteor.publish('attachmentsList', function(limit) {\n  return allAttachments(limit);\n});\n")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the access computation moves into a helper) ---
ACCESS = patched[patched.index("  const userId = this.userId;\n"):patched.index("  // Only return attachments for cards the user has access to\n")]
helper = '''function accessibleCardIds(userId) {
  const userBoards = ReactiveCache.getBoards({
    $or: [
      { permission: 'public' },
      { members: { $elemMatch: { userId, isActive: true } } }
    ]
  }).map(board => board._id);

  if (userBoards.length === 0) {
    return [];
  }

  return ReactiveCache.getCards({
    boardId: { $in: userBoards },
    archived: false
  }).map(card => card._id);
}

'''
v3 = swap(patched, ACCESS, "  const userCards = accessibleCardIds(this.userId);\n\n  if (userCards.length === 0) {\n    return this.ready();\n  }\n\n")
v3 = swap(v3, "Meteor.publish('attachmentsList', function(limit) {\n", helper + "Meteor.publish('attachmentsList', function(limit) {\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''// Public gallery: lists only boards flagged public, which anyone may see by design.
Meteor.publish('publicBoardsList', function(limit) {
  return ReactiveCache.getBoards(
    { permission: 'public', archived: false },
    {
      fields: { _id: 1, title: 1, permission: 1 },
      sort: { title: 1 },
      limit: limit,
    },
    true,
  ).cursor;
});
''')
