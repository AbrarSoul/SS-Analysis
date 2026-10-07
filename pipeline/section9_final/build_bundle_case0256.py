"""
Section 9 ground-truth test bundle: CASE-0256
(petl-developers/petl, petl/io/xml.py XmlView.__iter__, CVE-2020-29128,
CWE-91 (labelled; the real weakness is CWE-611 XML external entity
injection)).

Core vulnerable mechanism: `fromxml` reads an XML source with
`etree.parse(xmlf)`, no explicit parser. When lxml is available (the module
prefers it), the default `lxml.etree` parser resolves DTD-declared external
entities, so a document with
`<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` and `&xxe;` in a
value element has the file's contents substituted into the row petl yields to
the caller. Anyone who can supply the XML file that gets loaded (an upload, a
URL) can make the application read arbitrary local files (or, with an
`http://` SYSTEM id, request internal URLs) through petl's normal API. The
upstream fix parses with `etree.XMLParser(resolve_entities=False)` (falling
back to the default parser, `None`, only when that constructor call itself is
unsupported, i.e. `xml.etree.ElementTree` is in use) and lets a caller pass
their own `parser=` keyword.

Measured caveat, kept in the manifest notes: this environment's libxml2
(bundled with the installed lxml) refuses to fetch an external SYSTEM entity
(`file://` or `http://`) at all, with `resolve_entities` either way, so the
classic file-disclosure payload from the CVE report cannot be reproduced here;
`resolve_entities=False` is instead verified on an INTERNAL general entity,
where it demonstrably leaves the entity unexpanded (`.text` is `None`, the
entity survives as a child node) while the vulnerable default substitutes it
straight into `.text`, exactly the code path petl reads through
`attrgetter('text')`. `_create_xml_parser` returns `None` on `TypeError`, which
happens only when the stdlib `xml.etree.ElementTree` module -- whose `parse`
does not resolve external entities either way -- is in use; it never actually
falls back to an unsafe lxml parser.

Sibling sites: `etree.parse` is called once in the file; the class is
otherwise pure Python traversal.

Verification: `XmlView.__iter__` (and `_create_xml_parser` where present) is
extracted verbatim from each full file (used as the real, unmodified module;
`from lxml import etree` at the top resolves to the REAL `lxml.etree`), with a
stand-in `Table` base and `read_source_from_arg`. It is run on an XML document
whose DOCTYPE declares an INTERNAL general entity `&xxe;` with a marker value,
referenced from a value element; this environment's libxml2 refuses to fetch
an external SYSTEM entity (`file://`/`http://`) unconditionally, so an internal
entity is used as a faithful proxy for the same `resolve_entities` flag -- see
the caveat below.

Every variant is the FULL real file. `__iter__` implements the `Table`
iteration protocol used by `fromxml`'s caller, so its name and signature are
kept; the renamed variant renames locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0256"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


PARSE = "        with self.source.open('rb') as xmlf:\n\n            tree = etree.parse(xmlf)\n"
assert original.count(PARSE) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("    def __iter__(self):")
e = original.index("\ndef element_text_getter(")
seg = original[s:e]
import re
for a, b in (("vmatch", "value_path"), ("vdict", "value_dict"), ("xmlf", "handle"), ("tree", "doc")):
    # rename only the bare local identifier, never the self.<name> attribute access
    seg = re.sub(r"(?<!self\.)\b%s\b" % a, b, seg)
assert "value_path" in seg and "handle" in seg and "doc.iterfind" in seg
assert "self.value_path" not in seg and "self.value_dict" not in seg
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + seg + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, PARSE, "        with self.source.open('rb') as xmlf:\n\n            tree = _parse_xml(xmlf)\n")
v2 = swap(v2, "class XmlView(Table):", '''def _parse_xml(xmlf):
    return etree.parse(xmlf)


class XmlView(Table):''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, PARSE, "        with self.source.open('rb') as xmlf:\n\n            tree = etree.parse(xmlf, parser=_safe_parser())\n")
v3 = swap(v3, "class XmlView(Table):", '''def _safe_parser():
    """A parser that will not resolve DTD-declared external entities, when the
    installed etree module supports that keyword (lxml); otherwise None, which
    is safe as-is because xml.etree.ElementTree.parse never resolves them."""
    try:
        return etree.XMLParser(resolve_entities=False)
    except (TypeError, AttributeError):
        return None


class XmlView(Table):''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: parse a small, fixed configuration
XML string this process wrote itself, so no attacker-controlled document ever
reaches the parser."""
from lxml import etree


def own_config_value(name):
    doc = etree.fromstring(b"<config><entry name='x'>1</entry></config>")
    el = doc.find(".//entry[@name='%s']" % name)
    return el.text if el is not None else None
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
