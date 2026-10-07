"""
Section 9 ground-truth test bundle: CASE-0204
(jsreport/jsreport-chrome-pdf, lib/conversion.js the exported conversion
function around the page 'request' listener, CVE-2020-7762, CWE-22 local file
disclosure).

Located target: the `)` closing the `page.on('request', ...)` handler (the
locator's snippet is the end of that call).

Core vulnerable mechanism: the converter opens a Chrome page for user-controlled
HTML and only LOGS network requests (`page.on('request', ...)` writes a debug
line). Request interception is never enabled, so template content that
references `file:///etc/passwd` (an iframe, `<img>`, `<link>` or script) is loaded
by Chrome from the server's disk and ends up in the generated PDF/image. The
upstream fix enables `page.setRequestInterception(true)`, aborts requests
that start with `file:///` unless they are relative to the page's own `htmlUrl`, and
`continue()`s the rest.

Sibling sites: none in this file; the single request listener is the choke
point (the 'requestfinished' and 'requestfailed' listeners only log).

Verification: the whole module is executed in node with a fake browser/page
(an EventEmitter that records `setRequestInterception`, emits 'request' events
for a `file:///etc/passwd`, an https and a data: URL during `goto`, and records
which of them the module aborts or continues); real Chrome was not launched.

Every variant is the FULL real file. The exported function takes one options
object, so the renamed variant renames locals only.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0204"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

REQ = '''    page.on('request', (r) => {
      let detail = ''

      if (r.redirectChain().length > 0) {
        detail = ` (redirect from: ${trimUrl(r.redirectChain().slice(-1)[0].url())})`
      }

      pageLog('debug', `Page request: ${r.method()} (${r.resourceType()}) ${trimUrl(r.url())}${detail}`)
    })
'''
PAGE_NEW = '''    const page = await browser.newPage()

    if (executionInfo.error) {
      return
    }
'''
assert original.count(REQ) == 1 and original.count(PAGE_NEW) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
lines = []
for line in original.split("\n"):
    parts = re.split(r"""('(?:[^'\\]|\\.)*')""", line)
    for i in range(0, len(parts), 2):
        for old, new in (("page", "tab"), ("optionsToUse", "opts"), ("chromeVersion", "version")):
            parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
    lines.append("".join(parts))
v1 = "\n".join(lines)
assert "const tab = await browser.newPage()" in v1 and "tab.on('request', (r) => {" in v1 and "await tab.pdf(opts)" in v1.replace("result = await tab.pdf(opts)", "await tab.pdf(opts)")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, REQ, '''    page.on('request', logRequest)
''')
v2 = swap(v2, "  const conversionResult = await runWithTimeout(", '''  function logRequest (r) {
    let detail = ''

    if (r.redirectChain().length > 0) {
      detail = ` (redirect from: ${trimUrl(r.redirectChain().slice(-1)[0].url())})`
    }

    pageLog('debug', `Page request: ${r.method()} (${r.resourceType()}) ${trimUrl(r.url())}${detail}`)
  }

  const conversionResult = await runWithTimeout(''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Interception is on and ONLY http, https, data, blob and about requests (plus
# requests relative to the page's own htmlUrl) are continued; every other
# scheme (file:, ftp:, chrome:, ...) is aborted. Upstream aborts only URLs
# that start with file:///.
v3 = swap(original, PAGE_NEW, PAGE_NEW + '''
    await page.setRequestInterception(true)

    if (executionInfo.error) {
      return
    }
''')
v3 = swap(v3, REQ, '''    page.on('request', (r) => {
      let detail = ''

      if (r.redirectChain().length > 0) {
        detail = ` (redirect from: ${trimUrl(r.redirectChain().slice(-1)[0].url())})`
      }

      pageLog('debug', `Page request: ${r.method()} (${r.resourceType()}) ${trimUrl(r.url())}${detail}`)

      const relativeToHtmlUrl = r.url().lastIndexOf(htmlUrl, 0) === 0

      if (!relativeToHtmlUrl && !/^(https?|data|blob|about):/i.test(r.url())) {
        r.abort('accessdenied')
        return
      }

      r.continue()
    })
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign = '''"use strict";

/**
 * Same "describe a page request for the log" step as the conversion
 * listener's debug line, but it only FORMATS text; it starts nothing, loads
 * nothing and never touches the browser, so it cannot read a local file.
 */
function describeRequest(r) {
  return `Page request: ${r.method()} (${r.resourceType()}) ${r.url()}`;
}

module.exports = describeRequest;
'''
assert "only FORMATS text" in benign
(CASE_DIR / "benign_lookalike.js").write_text(benign)
print("Wrote 4 new samples for CASE-0204.")
