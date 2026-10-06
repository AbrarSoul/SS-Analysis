import Attachments from '/models/attachments';
import { ObjectID } from 'bson';

function accessibleCardIds(userId) {
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

Meteor.publish('attachmentsList', function(limit) {
  const userCards = accessibleCardIds(this.userId);

  if (userCards.length === 0) {
    return this.ready();
  }

  // Only return attachments for cards the user has access to
  const ret = ReactiveCache.getAttachments(
    { 'meta.cardId': { $in: userCards } },
    {
      fields: {
        _id: 1,
        name: 1,
        size: 1,
        type: 1,
        meta: 1,
        path: 1,
        versions: 1,
      },
      sort: {
        name: 1,
      },
      limit: limit,
    },
    true,
  ).cursor;
  return ret;
});
