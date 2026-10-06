import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class DefaultPom {

    private static final String TEMPLATE =
        "<project><modelVersion>4.0.0</modelVersion><version>0.0.1</version></project>";

    /**
     * Same DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(...)
     * chain as the pom parser, but the document is a constant embedded in the
     * source, so no attacker-controlled DOCTYPE or entity can reach the parser.
     */
    public static Document parseTemplate() throws Exception {
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(TEMPLATE.getBytes(StandardCharsets.UTF_8)));
    }
}
