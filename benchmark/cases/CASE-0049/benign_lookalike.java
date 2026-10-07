import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class SimpleScalarTypes
{
    public final static Set<String> KNOWN_SIMPLE_TYPE_NAMES;
    static {
        Set<String> s = new HashSet<String>();
        s.add("java.lang.String");
        s.add("java.lang.Integer");
        s.add("java.lang.Long");
        s.add("java.lang.Boolean");
        s.add("java.lang.Double");
        KNOWN_SIMPLE_TYPE_NAMES = Collections.unmodifiableSet(s);
    }

    public static boolean isSimpleScalar(String className)
    {
        return KNOWN_SIMPLE_TYPE_NAMES.contains(className);
    }
}
