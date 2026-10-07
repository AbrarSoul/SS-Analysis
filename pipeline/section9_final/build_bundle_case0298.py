"""
Section 9 ground-truth test bundle: CASE-0298
(streetwriters/notesnook, packages/editor/src/extensions/embed/component.tsx
tweetToEmbed, CVE-2026-31876, CWE-79 cross-site scripting).

Core vulnerable mechanism: the editor's embed extension renders a tweet
embed by building an HTML document string for an iframe `srcDoc`:
`<a href="${src}?ref_src=twsrc%5Etfw">`, where `src` is the URL the note's
author (or anyone who can edit / share a note, e.g. a collaborator or an
imported note) put in the embed node. `src` is interpolated into a
double-quoted attribute with no escaping, so a value containing a `"`
breaks out of the attribute: `https://x.com/a"><img src=x onerror=...>` (or
`" onmouseover="...`) injects markup and event handlers into the embed
document, giving script execution in the embed's frame (and, depending on
the iframe sandbox flags in use, in the app's origin). The upstream fix
builds the anchor with the DOM (`document.createElement('a')`, set `.href`)
and serializes it with `outerHTML`, which attribute-encodes the value.

Sibling sites: `tweetToEmbed` is the only place that builds embed HTML by
string concatenation; the other embed sources are passed through as `src`.

Verification: each full file's `tweetToEmbed` function is extracted
verbatim, transpiled with Node's `stripTypeScriptTypes` and run for real in
a REAL jsdom window (so `document.createElement`/`outerHTML` are the genuine
DOM implementation). The returned HTML string is then parsed by jsdom
(`div.innerHTML = html`) and inspected: the payload
`https://x.com/a"><img src=x onerror=alert(1)>` must not produce an `<img>`
element, and `" onmouseover="alert(1)` must not produce an `onmouseover`
attribute on any element. A benign URL must still yield an anchor whose
`href` is the tweet URL.

Every variant is the FULL real file. `tweetToEmbed` is called by name from
`EmbedComponent`, so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0298"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
patched = (CASE_DIR / "patched_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


FUNC = '''function tweetToEmbed(src: string, isDarkTheme: boolean) {
  src = src.replaceAll("x.com", "twitter.com");
  return `<blockquote class="twitter-tweet" data-dnt="true" ${
    isDarkTheme ? 'data-theme="dark"' : ""
  }><p lang="en" dir="ltr"><a href="${src}?ref_src=twsrc%5Etfw"></a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script> `;
}'''
assert original.count(FUNC) == 1

v1 = swap(original, FUNC, '''function tweetToEmbed(tweetUrl: string, isDarkTheme: boolean) {
  tweetUrl = tweetUrl.replaceAll("x.com", "twitter.com");
  return `<blockquote class="twitter-tweet" data-dnt="true" ${
    isDarkTheme ? 'data-theme="dark"' : ""
  }><p lang="en" dir="ltr"><a href="${tweetUrl}?ref_src=twsrc%5Etfw"></a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script> `;
}''')
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

v2 = swap(original, FUNC, '''function tweetLinkHtml(src: string) {
  return `<a href="${src}?ref_src=twsrc%5Etfw"></a>`;
}

function tweetToEmbed(src: string, isDarkTheme: boolean) {
  src = src.replaceAll("x.com", "twitter.com");
  return `<blockquote class="twitter-tweet" data-dnt="true" ${
    isDarkTheme ? 'data-theme="dark"' : ""
  }><p lang="en" dir="ltr">${tweetLinkHtml(src)}</blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script> `;
}''')
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

PFUNC = patched[patched.index("function tweetToEmbed"):]
PFUNC = PFUNC[:PFUNC.index("\n}") + 2]
assert PFUNC in patched
v3 = swap(patched, PFUNC, '''function tweetToEmbed(src: string, isDarkTheme: boolean) {
  src = src.replaceAll("x.com", "twitter.com");

  const anchor = document.createElement("a");
  anchor.setAttribute("href", `${src}?ref_src=twsrc%5Etfw`);
  const themeAttribute = isDarkTheme ? 'data-theme="dark"' : "";

  return `<blockquote class="twitter-tweet" data-dnt="true" ${themeAttribute}><p lang="en" dir="ltr">${anchor.outerHTML}</p></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script> `;
}''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

(CASE_DIR / "benign_lookalike.ts").write_text('''// Standalone example of the same shape: build a small HTML snippet from a
// FIXED, hard-coded set of themes (never user-supplied text), so nothing
// attacker-controlled is interpolated into markup.
const THEMES = { light: "#ffffff", dark: "#111111" } as const;

export function themedBadge(theme: keyof typeof THEMES) {
  return `<span class="badge" style="background:${THEMES[theme]}">note</span>`;
}
''')
