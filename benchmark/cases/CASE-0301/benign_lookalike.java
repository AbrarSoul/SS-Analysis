package io.onedev.server.migration;

import java.io.StringReader;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;

/**
 * Standalone example of the same shape: parse an XML document that ships
 * INSIDE the application jar (trusted, build-time content, never user
 * supplied), so default parser settings expose nothing.
 */
class BundledDefaultsParser {

    static Document parse(String bundledXml) throws DocumentException {
        return new SAXReader().read(new StringReader(bundledXml));
    }
}
