import javax.jcr.Repository;
import javax.naming.InitialContext;
import javax.naming.NamingException;

public class LocalRepositoryLocator {

    /** Fixed, developer-defined name in the container's own java:comp/env namespace. */
    private static final String REPOSITORY_JNDI_NAME = "java:comp/env/jcr/repository";

    /**
     * Same InitialContext.lookup(...) acquisition, but nothing the caller
     * passes reaches JNDI: the name is a constant and the environment is the
     * container's default (no caller-supplied factory or provider URL).
     */
    public Repository locate() {
        try {
            Object found = new InitialContext().lookup(REPOSITORY_JNDI_NAME);
            return found instanceof Repository ? (Repository) found : null;
        } catch (NamingException e) {
            return null;
        }
    }
}
