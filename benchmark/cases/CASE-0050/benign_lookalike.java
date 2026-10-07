import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class KnownModulePrefixes
{
    public final static Set<String> RECOGNIZED_MODULE_PACKAGE_PREFIXES;
    static {
        Set<String> s = new HashSet<String>();
        s.add("com.fasterxml.jackson.datatype");
        s.add("com.fasterxml.jackson.module");
        RECOGNIZED_MODULE_PACKAGE_PREFIXES = Collections.unmodifiableSet(s);
    }

    public static boolean isRecognizedModule(String packageName)
    {
        for (String prefix : RECOGNIZED_MODULE_PACKAGE_PREFIXES) {
            if (packageName.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
