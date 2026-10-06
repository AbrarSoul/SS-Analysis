// Standalone example of the same shape: a read-only route that intentionally
// uses only the login check because every logged-in user may see the same
// public list (release notes), with no per-role data.
function releaseNotesEndpoints(app, validatedRequest, loadNotes) {
  app.get("/notes/latest", [validatedRequest], async (_, response) => {
    response.status(200).json({ notes: await loadNotes() });
  });
}

module.exports = { releaseNotesEndpoints };
