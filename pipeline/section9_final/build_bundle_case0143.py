"""
Section 9 ground-truth test bundle: CASE-0143
(deeplook/svglib, svglib/svglib.py load_svg_file, CVE-2020-10799,
CWE-611 XML external entity (XXE) processing).

Core vulnerable mechanism: `load_svg_file(path)` parses untrusted SVG with
`etree.XMLParser(remove_comments=True, recover=True)`, leaving lxml's entity
handling at its default. On the lxml versions svglib supported at the time
(measured on lxml 4.9.4) the default RESOLVES entities, including
`<!ENTITY x SYSTEM "file:///...">`, so an SVG can pull a local file's
contents into a <text> node (and expand internal entities). The upstream fix
adds a `resolve_entities=False` parameter to `load_svg_file` and `svg2rlg`
and passes it to the parser.

Measured caveat, kept in the manifest notes: on lxml 6.1.3 the default no
longer resolves external entities (nothing is read from the file), so this
code is only exploitable on older lxml or when a caller requests resolution
(explicit `resolve_entities=True` does resolve on 6.1.3).

Sibling site: `ExternalSVG.__init__` (for <use xlink:href="other.svg">) and
`svg2rlg` both call `load_svg_file`, so the parser configuration inside
load_svg_file covers both; the safe variant fixes it there.

Every variant is the FULL real file with load_svg_file replaced.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0143"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

FN = '''def load_svg_file(path):
    parser = etree.XMLParser(remove_comments=True, recover=True)
    try:
        doc = etree.parse(path, parser=parser)
        svg_root = doc.getroot()
    except Exception as exc:
        logger.error("Failed to load input file! (%s)" % exc)
    else:
        return svg_root
'''
PARSER = "    parser = etree.XMLParser(remove_comments=True, recover=True)\n"
assert original.count(FN) == 1 and original.count("load_svg_file(") == 3


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, FN, '''def read_svg_document(svg_path):
    xml_parser = etree.XMLParser(remove_comments=True, recover=True)
    try:
        tree = etree.parse(svg_path, parser=xml_parser)
        root_element = tree.getroot()
    except Exception as err:
        logger.error("Failed to load input file! (%s)" % err)
    else:
        return root_element
''')
v1 = swap(v1, "        self.root_node = load_svg_file(path)\n", "        self.root_node = read_svg_document(path)\n")
v1 = swap(v1, "    svg_root = load_svg_file(path)\n", "    svg_root = read_svg_document(path)\n")
assert "load_svg_file" not in v1 and v1.count("read_svg_document") == 3
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, FN, '''def _new_svg_parser():
    return etree.XMLParser(remove_comments=True, recover=True)


def load_svg_file(path):
    try:
        return etree.parse(path, parser=_new_svg_parser()).getroot()
    except Exception as exc:
        logger.error("Failed to load input file! (%s)" % exc)
        return None
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Entity resolution, DTD loading and network access are all switched off in
# the parser inside load_svg_file, so both callers are covered and no
# signature changes; upstream instead threads a resolve_entities=False
# parameter through svg2rlg and load_svg_file.
v3 = swap(original, PARSER, '''    parser = etree.XMLParser(
        remove_comments=True,
        recover=True,
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
    )
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''from lxml import etree

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
'''
assert "_PLACEHOLDER_SVG" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0143.")
