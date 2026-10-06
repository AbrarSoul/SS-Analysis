import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class BundledScheme {

    private static final String SCHEME =
        "<Scheme LastUpgradeVersion=\"0900\"><BuildAction/></Scheme>";

    /**
     * Same DocumentBuilderFactory.newInstance() / parse(...) chain as the scheme
     * parser, but the XML is a constant embedded in the source, so no
     * attacker-controlled DOCTYPE or entity can reach the parser.
     */
    public static Document parseDefault() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(SCHEME.getBytes(StandardCharsets.UTF_8)));
    }
}
