r"""
Section 9 ground-truth test bundle: CASE-0331
(wekan/wekan, server/publications/activities.js activities publication,
CVE-2026-2207, CWE-200 exposure of sensitive information / CWE-284 improper
access control).

Core vulnerable mechanism: the `activities` publication (the board sidebar
and the card activity tab) checks that the subscriber is an admin of the board
`id`, and then also adds the ids of every board referenced by a
`cardType-linkedBoard` card on that board (`linkedElmtId.push(card.linkedId)`)
WITHOUT checking whether the subscriber may see those linked boards. A user who
administers one board can add a linked-board card that points at ANY other
board's id and then receives that private board's whole activity stream
(card titles, comments, member actions). In addition the permission check
resolves `id` as a board id even for `kind === 'card'` (where `id` is a card
id), so the card activity tab never works. The upstream fix resolves the board
per `kind`, requires `board.isVisibleBy(userId)`, and only adds linked boards
the user can see.

Sibling sites: none; the same board-visibility helper is used elsewhere in the
module scope.

Verification (REAL query engine): each full file is evaluated with node's `vm`
(import removed, `Meteor.publish` captured, `check`/`Match` no-ops, `this.userId`
and `this.ready` provided); a stand-in `ReactiveCache` runs
`getCards`/`getActivities` selectors and `sort`/`limit` with the real `mingo`
library. Data: private board A (u1 admin, u2 plain member), private board B
(nobody of them), public board C, linked-board cards on A pointing at B and C,
one activity on each board, and a card c1 on A with its own activity.
Subscribers: u1 on board A, u2 on board A and u1 on card c1.
Vulnerable variants give u1 the activities of A, B (private, unauthorised) and
C, give u2 nothing, and give the card subscriber nothing; patched/safe give u1
A and C only (not B), u2 A and C, and the card subscriber c1's activities.

Every variant is the FULL real file; the publication name `activities` is the
client API and stays.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0331"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant (locals renamed) ---
v1 = original
for old, new in [("linkedElmtId", "boardIds"), ("selector", "activityFilter"), ("ret", "feed")]:
    v1 = re.sub(r"(?<![\w.'\"`])%s(?![\w'\"`])" % old, new, v1)
assert v1.count("boardIds") == 4 and "return feed;" in v1 and "const feed = ReactiveCache" in v1
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (linked-board collection moved into a helper; still unchecked) ---
LINK = '''  // Get linkedBoard
  let linkedElmtId = [id];
  if (kind == 'board') {
    ReactiveCache.getCards({
      "type": "cardType-linkedBoard",
      "boardId": id}
      ).forEach(card => {
        linkedElmtId.push(card.linkedId);
    });
  }
'''
v2 = swap(original, LINK, "  const linkedElmtId = collectLinkedIds(kind, id);\n")
v2 = swap(v2, "Meteor.publish('activities', function(kind, id, limit, showActivities) {\n", '''function collectLinkedIds(kind, id) {
  const ids = [id];
  if (kind == 'board') {
    ReactiveCache.getCards({
      "type": "cardType-linkedBoard",
      "boardId": id}
      ).forEach(card => {
        ids.push(card.linkedId);
    });
  }
  return ids;
}

Meteor.publish('activities', function(kind, id, limit, showActivities) {
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the visible-linked-boards loop moves into a helper) ---
LOOP = '''    // Get linked boards, but only those visible to the user
    ReactiveCache.getCards({
      "type": "cardType-linkedBoard",
      "boardId": id
    }).forEach(card => {
      const linkedBoard = ReactiveCache.getBoard(card.linkedId);
      if (linkedBoard && linkedBoard.isVisibleBy(this.userId)) {
        linkedElmtId.push(card.linkedId);
      }
    });
'''
v3 = swap(patched, LOOP, "    linkedElmtId.push(...visibleLinkedBoardIds(id, this.userId));\n")
v3 = swap(v3, "Meteor.publish('activities', function(kind, id, limit, showActivities) {\n", '''function visibleLinkedBoardIds(boardId, userId) {
  const visible = [];
  ReactiveCache.getCards({
    "type": "cardType-linkedBoard",
    "boardId": boardId
  }).forEach(card => {
    const linkedBoard = ReactiveCache.getBoard(card.linkedId);
    if (linkedBoard && linkedBoard.isVisibleBy(userId)) {
      visible.push(card.linkedId);
    }
  });
  return visible;
}

Meteor.publish('activities', function(kind, id, limit, showActivities) {
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''import { ReactiveCache } from '/imports/reactiveCache';

// Public activity feed: the selector itself limits the stream to boards that are public, which
// anyone (even an anonymous visitor) may read by design, so no membership check is needed.
Meteor.publish('publicActivities', function(limit) {
  check(limit, Number);
  const publicBoardIds = ReactiveCache.getBoards({ permission: 'public' }).map(b => b._id);
  return ReactiveCache.getActivities(
    { boardId: { $in: publicBoardIds } },
    { limit, sort: { createdAt: -1 } },
    true,
  );
});
''')
