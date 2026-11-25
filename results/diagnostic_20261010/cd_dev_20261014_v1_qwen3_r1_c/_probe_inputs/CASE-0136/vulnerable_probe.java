    public File provide() throws IOException
    {
        File f_renamed = File.createTempFile(_prefix, _suffix);
        f_renamed.deleteOnExit();
        return f_renamed;
    }