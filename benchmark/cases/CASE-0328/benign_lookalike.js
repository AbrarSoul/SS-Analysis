// Public gallery: lists only boards flagged public, which anyone may see by design.
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
