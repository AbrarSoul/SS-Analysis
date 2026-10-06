import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class AllowListObjectInputStream
    extends ObjectInputStream
{
    private static final Set<String> ALLOWED = new HashSet<>(Arrays.asList(
        "java.util.ArrayList", "java.lang.Integer", "java.lang.Number", "[B"));

    public AllowListObjectInputStream(InputStream in)
        throws IOException
    {
        super(in);
    }

    /**
     * Same ObjectInputStream.resolveClass override as a "checking stream", but
     * EVERY class descriptor -- including the first -- must be on a fixed
     * allow-list before super.resolveClass is called, so no arbitrary class is
     * ever resolved or its deserialization logic run.
     */
    protected Class<?> resolveClass(ObjectStreamClass desc)
        throws IOException,
        ClassNotFoundException
    {
        if (!ALLOWED.contains(desc.getName()))
        {
            throw new InvalidClassException("unexpected class: ", desc.getName());
        }
        return super.resolveClass(desc);
    }
}
