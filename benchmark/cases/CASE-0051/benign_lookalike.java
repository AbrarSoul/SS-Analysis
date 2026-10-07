import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class DeprecatedAnnotationNames
{
    public final static Set<String> KNOWN_DEPRECATED_ANNOTATIONS;
    static {
        Set<String> s = new HashSet<String>();
        s.add("com.fasterxml.jackson.databind.annotation.JsonSerialize.Inclusion");
        s.add("com.fasterxml.jackson.databind.annotation.JsonTypeInfo.As.PROPERTY_LEGACY");
        KNOWN_DEPRECATED_ANNOTATIONS = Collections.unmodifiableSet(s);
    }

    public static boolean isDeprecated(String annotationClassName)
    {
        return KNOWN_DEPRECATED_ANNOTATIONS.contains(annotationClassName);
    }
}
