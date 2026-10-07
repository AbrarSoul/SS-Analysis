"""
Section 9 ground-truth test bundle: CASE-0260
(plantuml/plantuml, src/main/java/net/sourceforge/plantuml/directdot/
PSystemDot.java exportDiagramNow, CVE-2026-0858, CWE-79 stored cross-site
scripting through a Graphviz `@startdot` diagram rendered to SVG).

Core vulnerable mechanism: PlantUML lets a document embed a raw Graphviz DOT
graph (`@startdot`); `exportDiagramNow` hands that user-supplied `data` to
Graphviz after running it through `filter()`, a hand-rolled sanitizer meant to
strip `javascript:` URLs, `<script>` tags and `on*=` event-handler attributes.
`filter()`'s attribute sanitiser only matches DOUBLE-QUOTE-delimited attribute
values (`sanitizeDotAttribute`'s regex is `attrName\\s*=\\s*"([^"]*)"`), but
DOT/Graphviz also supports HTML-LIKE labels written with angle brackets
instead of quotes (`label=<...>`), and Graphviz renders those as literal HTML
inside an SVG `<foreignObject>`/text element. An event handler placed inside
such a bracket-delimited label (`label=<<table><tr><td
onmouseover="alert(document.domain)">x</td></tr></table>>`) never matches the
quote-only regex, so `filter()` leaves it untouched, and the SVG PlantUML
renders runs it the moment a victim hovers the diagram in a browser. The
upstream fix does not try to patch the filter: it removes `filter()` and its
two helpers outright and instead refuses to render `FileFormat.SVG` at all
(`if (fileFormat.getFileFormat() == FileFormat.SVG) return
ImageDataSimple.ok();`), because non-SVG output (PNG, ...) cannot carry live
script.

Measured caveat, kept in the manifest notes: upstream's `filter()` removal
also stops sanitising input for every OTHER output format; PNG/PDF renders of
a malicious `@startdot` still contain the raw payload text baked into the
raster/vector output (as pixels/paths, not executable markup) -- harmless for
XSS, but the "javascript:" and event-handler TEXT is not scrubbed from
whatever textual representation the renderer might also produce.

Sibling sites: `filter()` is the only place the vulnerable file sanitises
`data`, and `exportDiagramNow` is the only place `filter()` is called; there
is one call site to change.

Verification: two things are checked against each full file. (1) `filter`,
`sanitizeDotAttribute` and `sanitizeAttributeValue` (present in the
vulnerable/renamed/restructured variants) are extracted verbatim and run, as
real unmodified Java string-processing code (no stubs needed), on a DOT
fragment whose HTML-like label carries `onmouseover=` and a `javascript:`
URL, to see whether either survives. (2) `exportDiagramNow` itself is
extracted into a class compiled with javac against minimal stand-in
PlantUML/Graphviz types (`FileFormat`, `FileFormatOption`,
`GraphvizRuntimeEnvironment`/`Graphviz`, `ImageBuilder`, `ImageDataSimple`,
...) whose `GraphvizRuntimeEnvironment.getInstance().createForSystemDot(...)`
records whether it was reached; `exportDiagramNow` is invoked (via
reflection, since it is `protected`) once with `FileFormat.SVG` and once with
`FileFormat.PNG`.

Every variant is the FULL real file. `exportDiagramNow` overrides
`AbstractPSystem`'s template method and is invoked by the PlantUML export
pipeline, so its name and signature are kept; the renamed variant renames
locals and the sanitiser's parameters.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0260"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


EXPORT = '''	final protected ImageData exportDiagramNow(OutputStream os, int num, FileFormatOption fileFormat)
			throws IOException {
		final Graphviz graphviz = GraphvizRuntimeEnvironment.getInstance().createForSystemDot(null, filter(data),
				StringUtils.goLowerCase(fileFormat.getFileFormat().name()));
'''
assert original.count(EXPORT) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, EXPORT, '''	final protected ImageData exportDiagramNow(OutputStream out, int num, FileFormatOption format)
			throws IOException {
		final Graphviz graphviz = GraphvizRuntimeEnvironment.getInstance().createForSystemDot(null, filter(data),
				StringUtils.goLowerCase(format.getFileFormat().name()));
''')
v1 = v1.replace(
    "\t\t\treturn ImageBuilder.create(fileFormat, result).seed(seed()).status(FileImageData.CRASH).write(os);\n\t\t}\n\n\t\tfinal CounterOutputStream counter = new CounterOutputStream(os);",
    "\t\t\treturn ImageBuilder.create(format, result).seed(seed()).status(FileImageData.CRASH).write(out);\n\t\t}\n\n\t\tfinal CounterOutputStream counter = new CounterOutputStream(out);",
)
v1 = v1.replace(
    "\t\t\treturn ImageBuilder.create(fileFormat, result).seed(seed()).status(FileImageData.CRASH).write(os);\n\t\t}\n\n\t\treturn ImageDataSimple.ok();",
    "\t\t\treturn ImageBuilder.create(format, result).seed(seed()).status(FileImageData.CRASH).write(out);\n\t\t}\n\n\t\treturn ImageDataSimple.ok();",
)
assert "OutputStream out, int num, FileFormatOption format" in v1
v1 = swap(v1, "\tprivate String filter(String data) {\n", "\tprivate String filter(String dotSource) {\n")
v1 = v1.replace("data = data.replaceAll", "dotSource = dotSource.replaceAll")
v1 = v1.replace("return data;\n\t}\n\n\tprivate String sanitizeDotAttribute", "return dotSource;\n\t}\n\n\tprivate String sanitizeDotAttribute")
v1 = v1.replace("data = sanitizeDotAttribute(data,", "dotSource = sanitizeDotAttribute(dotSource,")
assert "dotSource = dotSource.replaceAll" in v1 and "return dotSource;" in v1
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, EXPORT, '''	final protected ImageData exportDiagramNow(OutputStream os, int num, FileFormatOption fileFormat)
			throws IOException {
		final Graphviz graphviz = buildGraphviz(fileFormat);
''')
v2 = swap(v2, "\tprivate String filter(String data) {", '''	private Graphviz buildGraphviz(FileFormatOption fileFormat) {
		return GraphvizRuntimeEnvironment.getInstance().createForSystemDot(null, filter(data),
				StringUtils.goLowerCase(fileFormat.getFileFormat().name()));
	}

	private String filter(String data) {''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "import net.sourceforge.plantuml.AbstractPSystem;\n",
          "import net.sourceforge.plantuml.AbstractPSystem;\nimport net.sourceforge.plantuml.FileFormat;\n")
v3 = swap(v3, EXPORT, '''	final protected ImageData exportDiagramNow(OutputStream os, int num, FileFormatOption fileFormat)
			throws IOException {

		if (isScriptCapableFormat(fileFormat))
			return ImageDataSimple.ok();

		final Graphviz graphviz = GraphvizRuntimeEnvironment.getInstance().createForSystemDot(null, data,
				StringUtils.goLowerCase(fileFormat.getFileFormat().name()));
''')
v3 = swap(v3, "\tprivate String filter(String data) {\n\t\tdata = data.replaceAll(\"(?i)\\\\bjavascript:\", \"js:\");\n\n\t\tdata = data.replaceAll(\"(?i)<\\\\s*/?\\\\s*script[^>]*>\", \"\");\n\n\t\tdata = sanitizeDotAttribute(data, \"fontname\");\n\t\tdata = sanitizeDotAttribute(data, \"label\");\n\t\tdata = sanitizeDotAttribute(data, \"xlabel\");\n\t\tdata = sanitizeDotAttribute(data, \"URL\");\n\t\tdata = sanitizeDotAttribute(data, \"href\");\n\t\tdata = sanitizeDotAttribute(data, \"tooltip\");\n\n\t\treturn data;\n\t}\n\n\tprivate String sanitizeDotAttribute(String dot, String attrName) {\n\t\tfinal Pattern p = Pattern.compile(\"(?i)(\" + attrName + \")\\\\s*=\\\\s*\\\"([^\\\"]*)\\\"\");\n\t\tfinal Matcher m = p.matcher(dot);\n\t\tfinal StringBuffer sb = new StringBuffer();\n\t\twhile (m.find()) {\n\t\t\tfinal String originalValue = m.group(2);\n\t\t\tfinal String safeValue = sanitizeAttributeValue(originalValue);\n\t\t\tm.appendReplacement(sb, m.group(1) + \"=\\\"\" + safeValue + \"\\\"\");\n\t\t}\n\t\tm.appendTail(sb);\n\t\treturn sb.toString();\n\t}\n\n\tprivate String sanitizeAttributeValue(String value) {\n\t\tvalue = value.replace(\"<\", \"\").replace(\">\", \"\");\n\t\tvalue = value.replace(\"\\\"\", \"\").replace(\"'\", \"\");\n\t\tvalue = value.replaceAll(\"(?i)on[a-z]+\\\\s*=\", \"\");\n\n\t\treturn value;\n\t}\n",
          '''	/**
	 * SVG can embed live markup (HTML-like labels, event-handler attributes) that a
	 * browser executes on open; every other PlantUML output format cannot.
	 */
	private static boolean isScriptCapableFormat(FileFormatOption fileFormat) {
		return fileFormat.getFileFormat() == FileFormat.SVG;
	}
''')
v3 = swap(v3, "import java.util.regex.Matcher;\nimport java.util.regex.Pattern;\n\n", "")
(CASE_DIR / "variant_safe_01.java").write_text(v3)

BENIGN = '''package net.sourceforge.plantuml.directdot;

/**
 * Standalone example of the same shape: a format gate that skips an expensive
 * or format-specific step, but for a purely cosmetic reason (some renderers
 * do not support a decorative watermark), not a security boundary.
 */
public class WatermarkGate {

    public static boolean supportsWatermark(String rendererName) {
        return !"ascii-art".equals(rendererName);
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN)
