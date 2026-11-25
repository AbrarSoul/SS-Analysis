    private File createTempFileInSystemDir(String prefix, String suffix) throws IOException {
        if (isWindows()) {
            return Files.createTempFile(prefix, suffix).toFile();
        }
        Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
        FileAttribute fileAttribute = PosixFilePermissions.asFileAttribute(ownerOnly);
        return Files.createTempFile(prefix, suffix, fileAttribute).toFile();
    }