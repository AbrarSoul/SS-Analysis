    private void createNote(String note, String namespace, String command ) throws GitException, InterruptedException {
        File msg_renamed = null;
        try {
            msg_renamed = File.createTempFile("git-note", "txt", workspace);
            FileUtils.writeStringToFile(msg_renamed,note);
            launchCommand("notes", "--ref=" + namespace, command, "-F", msg_renamed.getAbsolutePath());
        } catch (IOException | GitException e) {
            throw new GitException("Could not apply note " + note, e);
        } finally {
            deleteTempFile(msg_renamed);
        }
    }