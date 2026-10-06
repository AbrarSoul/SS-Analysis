package org.traccar.protocol;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Standalone example of the same shape: parse an XML resource that ships
 * inside the application jar (trusted build-time content, never
 * device-supplied), so default parser settings expose nothing.
 */
class BundledConfigParser {

    static DocumentBuilder builder() throws ParserConfigurationException {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder();
    }
}
