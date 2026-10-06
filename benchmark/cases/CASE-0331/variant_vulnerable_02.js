import { ReactiveCache } from '/imports/reactiveCache';

// We use activities fields at two different places:
// 1. The board sidebar
// 2. The card activity tab
// We use this publication to paginate for these two publications.

function collectLinkedIds(kind, id) {
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

  // Check user permissions - only BoardAdmin can view activities
  if (this.userId) {
    const user = ReactiveCache.getUser(this.userId);
    const board = ReactiveCache.getBoard(id);
    
    if (user && board) {
      // Find user membership in board
      const membership = board.members.find(m => m.userId === this.userId);
      
      // Only BoardAdmin can view activities
      if (!membership || !membership.isAdmin) {
        return this.ready();
      }
    } else {
      // If board or user not found, deny
      return this.ready();
    }
  } else {
    // If not logged in, deny
    return this.ready();
  }

  const linkedElmtId = collectLinkedIds(kind, id);

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
