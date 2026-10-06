// Board-template creation: the permission is fixed by the server, never taken from the request.
if (Meteor.isServer) {
  JsonRoutes.add('POST', '/api/board-templates', function(req, res) {
    Authentication.checkLoggedIn(req.userId);
    const id = Boards.insert({
      title: req.body.title,
      members: [{ userId: req.userId, isAdmin: true, isActive: true }],
      permission: 'private',
      type: 'template-board',
    });
    JsonRoutes.sendResult(res, { code: 200, data: { _id: id } });
  });
}
