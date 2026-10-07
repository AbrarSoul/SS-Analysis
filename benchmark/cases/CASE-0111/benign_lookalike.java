package org.jcp.xml.dsig.internal.dom;

import java.security.InvalidAlgorithmParameterException;

import javax.xml.crypto.dsig.TransformService;

/**
 * Same "constructor that just hands a TransformService to DOMTransform"
 * shape, but this class models a generic ds:Transform, which is DESIGNED to
 * accept any transform algorithm (XPath, XSLT, base64, ...). Unlike a
 * CanonicalizationMethod there is no narrower algorithm family to enforce
 * here, so passing the service straight through is correct.
 */
public class DOMGenericTransform extends DOMTransform {

    public DOMGenericTransform(TransformService spi)
        throws InvalidAlgorithmParameterException {
        super(spi);
    }
}
