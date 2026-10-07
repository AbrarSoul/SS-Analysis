"""
Section 9 ground-truth test bundle: CASE-0118
(apache/tomcat, CGIServlet.CGIEnvironment.findCGI, CVE-2025-46701,
CWE-178 improper handling of case sensitivity).

Core vulnerable mechanism: `findCGI()` walks the request's pathInfo
segments and stops at the FIRST thing `ServletContext.getResource(path)`
returns -- a directory counts just as much as a script -- and then uses
`context.getRealPath(cgiPath)`, which echoes the case the CLIENT typed,
as the file to execute. On a case-insensitive file system a request such as
`/cgi-bin/HELLO.CGI` therefore resolves to hello.cgi while every URL-based
security constraint (matched case-sensitively on the request path) was
written for the real name, so the constraint is bypassed; and a directory
segment can be mistaken for the script. The upstream fix switches to
`WebResourceRoot.getResource(...)`, keeps walking until `isFile()`, and
uses `getCanonicalPath()` (real-case path).

Every variant is the FULL real file with findCGI replaced. findCGI is a
protected method of the nested CGIEnvironment class with one in-file call
site (its constructor), which the renamed variant also renames. The safe
variant achieves the same with ServletContext + java.io.File only, so it
needs no new WebResourceRoot field or init() change.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0118"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "        protected String[] findCGI(String contextPath, String servletPath, String pathInfo, String cgiPathPrefix) {\n"
s = original.index(HDR)
e = original.index("\n        }\n", s) + len("\n        }\n")
BLOCK = original[s:e]
CALL = "sCGINames = findCGI(contextPath, servletPath, sPathInfoOrig, cgiPathPrefix);"
LOOKUP = '''                try {
                    cgiScriptURL = context.getResource(cgiPath.toString());
                } catch (MalformedURLException e) {
                    // Ignore - should never happen
                }
'''
REALPATH = "            path = context.getRealPath(cgiPath.toString());\n"
assert original.count(HDR) == 1 and original.count(CALL) == 1 and original.count("findCGI(") == 2
assert BLOCK.count(LOOKUP) == 1 and BLOCK.count(REALPATH) == 1


def build(new_block, extra_after=None, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + (extra_after or "") + original[e:]
    if new_call:
        assert out.count(CALL) == 1
        out = out.replace(CALL, new_call)
    return out


def rename_outside_comments_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        st = line.lstrip()
        if st.startswith("//") or st.startswith("*") or st.startswith("/*"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("findCGI(", "locateCgiScript(")
b = rename_outside_comments_strings(b, (("cgiPath", "resourcePath"), ("urlPath", "publicPath"), ("cgiScriptURL", "scriptUrl"),
                                        ("pathWalker", "segments"), ("urlSegment", "part"), ("tmpCgiFile", "expandedFile"),
                                        ("path", "fsPath"), ("scriptName", "publicName"), ("cgiName", "relativeName")))
assert "context.getResource(resourcePath.toString())" in b and "context.getRealPath(resourcePath.toString())" in b
assert "locateCgiScript(String contextPath" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(
    build(b, new_call="sCGINames = locateCgiScript(contextPath, servletPath, sPathInfoOrig, cgiPathPrefix);"))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(LOOKUP, "                cgiScriptURL = lookupResource(cgiPath.toString());\n")
helper = '''
        private URL lookupResource(String resourcePath) {
            try {
                return context.getResource(resourcePath);
            } catch (MalformedURLException e) {
                // Ignore - should never happen
                return null;
            }
        }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# Same three effects as upstream using ServletContext + File only: only a
# regular FILE ends the walk, and the executed path is the canonical
# (real-case) one.
b = BLOCK.replace(LOOKUP, '''                try {
                    URL candidate = context.getResource(cgiPath.toString());
                    if (candidate != null && isRegularFile(cgiPath.toString())) {
                        cgiScriptURL = candidate;
                    }
                } catch (MalformedURLException e) {
                    // Ignore - should never happen
                }
''').replace(REALPATH, REALPATH + '''            if (path != null) {
                try {
                    path = new File(path).getCanonicalPath();
                } catch (IOException ioe) {
                    return new String[] { null, null, null, null };
                }
            }
''')
helper = '''
        private boolean isRegularFile(String resourcePath) {
            String real = context.getRealPath(resourcePath);
            if (real != null) {
                return new File(real).isFile();
            }
            // Not on the file system (e.g. inside an archive): the servlet
            // context only hands out a stream for files, never for directories.
            try (InputStream probe = context.getResourceAsStream(resourcePath)) {
                return probe != null;
            } catch (IOException ioe) {
                return false;
            }
        }
'''
safe_source = build(b, extra_after=helper)
assert "getCanonicalPath()" in safe_source and "isRegularFile(" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.File;
import java.io.IOException;
import java.util.StringTokenizer;

public class ContentFileLocator {

    private final File contentRoot;

    public ContentFileLocator(File contentRoot) throws IOException {
        this.contentRoot = contentRoot.getCanonicalFile();
    }

    /**
     * Same "walk the path segments until something matches" shape as a CGI
     * script search, but it only stops at a regular FILE, and it hands back
     * the CANONICAL path after checking it is still inside the content root,
     * so neither a directory, a differently-cased spelling, nor "../" can
     * change what is served. Nothing found is reported as null.
     */
    public File find(String pathInfo) throws IOException {
        File current = contentRoot;
        StringTokenizer walker = new StringTokenizer(pathInfo, "/");
        while (walker.hasMoreElements()) {
            current = new File(current, walker.nextToken());
            if (current.isFile()) {
                File canonical = current.getCanonicalFile();
                return canonical.getPath().startsWith(contentRoot.getPath() + File.separator) ? canonical : null;
            }
        }
        return null;
    }
}
'''
assert "getCanonicalFile()" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0118.")
