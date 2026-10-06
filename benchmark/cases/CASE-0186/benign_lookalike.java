import java.io.File;

public class FixedJobDirs {

    private final File jobsDir;

    public FixedJobDirs(File jobsDir) {
        this.jobsDir = jobsDir;
    }

    /**
     * Same "new File(jobsDir, name).mkdirs()" mapping as job creation, but the
     * name is chosen from a fixed list of built-in template names, never from
     * the command line, so it cannot contain path elements.
     */
    public File createTemplateDir(int templateIndex) {
        String[] templates = {"freestyle", "pipeline", "folder"};
        File dir = new File(jobsDir, templates[templateIndex]);
        dir.mkdirs();
        return dir;
    }
}
