    public File provide() throws IOException
    {
        File f_renamed = Files.createTempFile(_prefix, _suffix).toFile();
        f_renamed.deleteOnExit();
        return f_renamed;
    }