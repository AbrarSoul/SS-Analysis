from lxml import etree

# Fixed, developer-written markup: no external input ever reaches the parser.
_PLACEHOLDER_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16">'
    b'<rect width="16" height="16" fill="#cccccc"/></svg>'
)


def load_placeholder_drawing():
    """Same XMLParser(remove_comments=True, recover=True) + parse shape as an
    SVG loader, but the document is a constant embedded in the source, so
    there is no attacker-controlled DOCTYPE or entity to resolve."""
    parser = etree.XMLParser(remove_comments=True, recover=True)
    return etree.fromstring(_PLACEHOLDER_SVG, parser=parser)
