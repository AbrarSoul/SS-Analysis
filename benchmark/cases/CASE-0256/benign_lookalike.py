"""Standalone example of the same shape: parse a small, fixed configuration
XML string this process wrote itself, so no attacker-controlled document ever
reaches the parser."""
from lxml import etree


def own_config_value(name):
    doc = etree.fromstring(b"<config><entry name='x'>1</entry></config>")
    el = doc.find(".//entry[@name='%s']" % name)
    return el.text if el is not None else None
