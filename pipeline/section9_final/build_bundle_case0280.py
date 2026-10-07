"""
Section 9 ground-truth test bundle: CASE-0280
(run-llama/llama_index, llama-index-integrations/readers/llama-index-readers-
web/llama_index/readers/web/knowledge_base/base.py
KnowledgeBaseWebReader.get_article_urls, CVE-2025-1752, CWE-674 uncontrolled
recursion). This is the real follow-up fix: the earlier CVE-2024-12910
commit for the same function added a max_depth parameter but never enforced
it (measured: still unbounded), so that pair was excluded from the dataset.

Core vulnerable mechanism: `get_article_urls` crawls a knowledge base by
recursively following every link found on each page (`self.get_article_urls(
browser, root_url, url, max_depth)`), with `max_depth` accepted but never
compared to anything and never decremented. A site whose pages link to each
other in a cycle (an ordinary "related articles"/breadcrumb structure, or a
hostile site) drives the recursion forever: RecursionError / process crash
(DoS) or endless crawling. The upstream fix adds a `depth` counter parameter,
returns `[]` when `depth >= max_depth`, and passes `depth + 1` down.

Sibling sites: `get_article_urls` is the only recursive function in the
file; `load_data` calls it once.

Verification: each full file's `get_article_urls` method (plus any helper
defined after it) is extracted verbatim into a stand-in class and run as
real Python against a stub Playwright browser whose pages each link back to
themselves (a cycle) with `sys.setrecursionlimit(500)`: the number of pages
opened and whether RecursionError occurred is measured with `max_depth=5`.
A second, acyclic two-level site (control) confirms normal crawling still
finds the article.

Every variant is the FULL real file. `get_article_urls` is called by name
from `load_data`, so its name and signature are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0280"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


LOOP = '''        # Otherwise crawl this page and find all the articles linked from it
        article_urls = []
        links = []

        for link_selector in self.link_selectors:
            ahrefs = page.query_selector_all(link_selector)
            links.extend(ahrefs)

        for link in links:
            url = root_url + page.evaluate("(node) => node.getAttribute('href')", link)
            article_urls.extend(
                self.get_article_urls(browser, root_url, url, max_depth)
            )

        page.close()

        return article_urls
'''
assert original.count(LOOP) == 1

v1 = swap(original, LOOP, '''        # Otherwise crawl this page and find all the articles linked from it
        found_urls = []
        anchors = []

        for link_selector in self.link_selectors:
            ahrefs = page.query_selector_all(link_selector)
            anchors.extend(ahrefs)

        for anchor in anchors:
            target = root_url + page.evaluate("(node) => node.getAttribute('href')", anchor)
            found_urls.extend(
                self.get_article_urls(browser, root_url, target, max_depth)
            )

        page.close()

        return found_urls
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

v2 = swap(original, LOOP, '''        # Otherwise crawl this page and find all the articles linked from it
        article_urls = []
        for url in self._linked_urls(page, root_url):
            article_urls.extend(
                self.get_article_urls(browser, root_url, url, max_depth)
            )

        page.close()

        return article_urls

    def _linked_urls(self, page: Any, root_url: str) -> List[str]:
        links = []
        for link_selector in self.link_selectors:
            links.extend(page.query_selector_all(link_selector))
        return [
            root_url + page.evaluate("(node) => node.getAttribute('href')", link)
            for link in links
        ]
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

v3 = swap(original, LOOP, LOOP.replace("max_depth)\n", "max_depth, depth + 1)\n"))
v3 = swap(v3, "self, browser: Any, root_url: str, current_url: str, max_depth: int = 100\n    ) -> List[str]:",
          "self,\n        browser: Any,\n        root_url: str,\n        current_url: str,\n        max_depth: int = 100,\n        depth: int = 0,\n    ) -> List[str]:")
v3 = swap(v3, '        page = browser.new_page(ignore_https_errors=True)\n        page.set_default_timeout(60000)\n        page.goto(current_url, wait_until="domcontentloaded")\n',
          '        if depth + 1 > max_depth:\n            return []\n\n        page = browser.new_page(ignore_https_errors=True)\n        page.set_default_timeout(60000)\n        page.goto(current_url, wait_until="domcontentloaded")\n')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""
Standalone example of the same shape: a recursive directory sizer that
recurses on real, finite filesystem trees from a caller-supplied root
(no attacker-controlled link graph, no cycles since symlinks are skipped),
so unbounded depth is not an input-driven risk.
"""
import os


def tree_size(path):
    total = 0
    for entry in os.scandir(path):
        if entry.is_symlink():
            continue
        if entry.is_dir():
            total += tree_size(entry.path)
        else:
            total += entry.stat().st_size
    return total
''')
