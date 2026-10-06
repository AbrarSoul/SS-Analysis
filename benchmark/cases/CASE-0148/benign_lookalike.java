import java.io.StringReader;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;
import org.xml.sax.InputSource;

public class BundledConfig {

    /** Fixed, developer-written XML: no external input ever reaches the parser. */
    private static final String DEFAULTS = "<config><timeout>30</timeout></config>";

    /**
     * Same new SAXReader() + read(InputSource) shape as DocumentHelper.parseText,
     * but the text is a constant in the source, so there is no attacker
     * controlled DOCTYPE or entity to resolve.
     */
    public static Document defaults() throws DocumentException {
        SAXReader reader = new SAXReader();
        return reader.read(new InputSource(new StringReader(DEFAULTS)));
    }
}
