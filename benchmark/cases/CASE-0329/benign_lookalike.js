// Site-administrator maintenance route: may edit ANY custom field by id, but only for site admins
// (the caller's privilege, not a board in the URL, is what is checked).
if (Meteor.isServer) {
  JsonRoutes.add('PUT', '/api/admin/custom-fields/:customFieldId', (req, res) => {
    Authentication.checkAdmin(req.userId);
    const paramFieldId = req.params.customFieldId;
    CustomFields.direct.update({ _id: paramFieldId }, { $set: { name: req.body.name } });
    JsonRoutes.sendResult(res, { code: 200, data: { _id: paramFieldId } });
  });
}
