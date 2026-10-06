import { ReactiveCache } from '/imports/reactiveCache';

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
