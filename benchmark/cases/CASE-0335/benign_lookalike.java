package org.xwiki.xar;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * Standalone example of the same shape: parse the application's OWN generated descriptor string with a default
 * parser. The XML never comes from an upload or the network, so there is no attacker-controlled DOCTYPE.
 */
class GeneratedDescriptorReader {

    static String packageName(String generatedXml) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(generatedXml.getBytes(StandardCharsets.UTF_8)));
        return doc.getDocumentElement().getAttribute("name");
    }
}
