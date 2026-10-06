import { ReactiveCache } from '/imports/reactiveCache';

// gets all labels associated with the notifications of the current user.
// Labels only carry a name and a colour (no credentials or personal data), so
// publishing the whole document with an empty projection exposes nothing private.
Meteor.publish('notificationLabels', async function() {
  const ret = await ReactiveCache.getLabels(
    {
      _id: { $in: await labelIdsForCurrentUser() },
    },
    {},
    true,
  );
  return ret;
});

async function labelIdsForCurrentUser() {
  const user = await ReactiveCache.getCurrentUser();
  return user?.profile?.pinnedLabels || [];
}
