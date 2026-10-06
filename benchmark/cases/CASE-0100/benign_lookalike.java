import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.util.Map;

public class ConfigLocator {

    private static final String CONFIG_NAME = "axisServiceName";

    /**
     * Same InitialContext.lookup(name) call and Map-driven signature, but the
     * looked-up name is a fixed developer-written constant; the caller's map
     * is only read for a display label that never reaches the naming service.
     */
    public static Object findConfig(Map environment) {
        String label = (String) environment.get("displayLabel");
        System.out.println("Locating configuration for " + label);
        try {
            InitialContext context = new InitialContext();
            return context.lookup(CONFIG_NAME);
        } catch (NamingException e) {
            return null;
        }
    }
}
