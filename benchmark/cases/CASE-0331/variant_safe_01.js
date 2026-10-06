import { ReactiveCache } from '/imports/reactiveCache';

// We use activities fields at two different places:
// 1. The board sidebar
// 2. The card activity tab
// We use this publication to paginate for these two publications.

function visibleLinkedBoardIds(boardId, userId) {
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
  check(
    kind,
    Match.Where(x => {
      return ['board', 'card'].indexOf(x) !== -1;
    }),
  );
  check(id, Match.Maybe(String));
  check(limit, Number);
  check(showActivities, Boolean);

  // Return empty cursor if id is null or undefined
  if (!id) {
    return this.ready();
  }

  if (!this.userId) {
    return this.ready();
  }

  let linkedElmtId = [id];
  let board;

  if (kind === 'board') {
    board = ReactiveCache.getBoard(id);
    if (!board || !board.isVisibleBy(this.userId)) {
      return this.ready();
    }

    linkedElmtId.push(...visibleLinkedBoardIds(id, this.userId));
  } else if (kind === 'card') {
    const card = ReactiveCache.getCard(id);
    if (!card) {
      return this.ready();
    }
    board = ReactiveCache.getBoard(card.boardId);
    if (!board || !board.isVisibleBy(this.userId)) {
      return this.ready();
    }
  }

  const selector = showActivities
    ? { [`${kind}Id`]: { $in: linkedElmtId } }
    : { $and: [{ activityType: 'addComment' }, { [`${kind}Id`]: { $in: linkedElmtId } }] };
  const ret = ReactiveCache.getActivities(selector,
    {
      limit,
      sort: { createdAt: -1 },
    },
    true,
  );
  return ret;
});
