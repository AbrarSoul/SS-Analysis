"""
Section 9 ground-truth test bundle: CASE-0200
(jitsi/jitsi, .../browserlauncher/BrowserLauncherImpl.java openURL,
CVE-2022-43550, CWE-77 / CWE-78 command injection).

Core vulnerable mechanism: `openURL(String url)` passes the caller's string to
`launchBrowser`, which on Windows runs
`Runtime.exec("rundll32 url.dll,FileProtocolHandler " + url)` and on Linux
`Runtime.exec(new String[]{browser, url})`. Nothing checks that `url` is a web
URL, so an attacker-supplied link (for example one received in a chat
message) such as `file:///C:/Windows/System32/calc.exe`, `\\\\host\\share\\x.exe`
or a `-`-prefixed value is handed to the OS URL handler / browser, which opens
or executes it. The upstream fix returns early unless
`url != null && url.startsWith("http")`.

Measured caveat, kept in the manifest notes: `startsWith("http")` also
accepts schemes and hosts such as `httpx://...` or `http-evil:...` (any string
beginning with "http"), so the check is a prefix test, not a scheme test. The
safe variant parses the value with `java.net.URI` and requires the scheme to be
exactly http or https with a host.

Sibling sites: launchBrowser is private and only reached from openURL, so the
single gate in openURL covers both the Windows and the Linux branch.

Verification: openURL and launchBrowser are extracted into a harness in which
`Runtime` is shadowed by a recording class (no process is started) and
SystemUtils.IS_OS_WINDOWS is set, so the exact command line that would be
executed is captured.

Every variant is the FULL real file. openURL implements BrowserLauncherService,
so the renamed variant keeps its name and renames its parameter and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0200"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

s = original.index("    public void openURL(final String url)\n")
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
assert original.count("launchBrowser(url)") == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("final String url", "final String address").replace("launchBrowser(url)", "launchBrowser(address)")
b = b.replace("Thread launchBrowserThread", "Thread worker").replace("launchBrowserThread.start();", "worker.start();").replace("catch (Exception e)", "catch (Exception failure)").replace('"Failed to launch browser", e)', '"Failed to launch browser", failure)')
assert "openURL(final String address)" in b and "worker.start();" in b and "failure" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = '''    public void openURL(final String url)
    {
        Thread launchBrowserThread = new Thread(() ->
        {
            try
            {
                launchBrowser(url);
            }
            catch (Exception e)
            {
                logger.error("Failed to launch browser", e);
            }
        }, getClass().getName());

        launchBrowserThread.start();
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# The value must parse as a java.net.URI whose scheme is exactly http or https
# and that has a host; upstream tests startsWith("http").
b = BLOCK.replace("    {\n        Thread launchBrowserThread\n", '''    {
        if (!isWebUrl(url))
        {
            logger.warn("Not a valid URL to open:" + url);
            return;
        }
        Thread launchBrowserThread
''', 1)
helper = '''
    private static boolean isWebUrl(String url)
    {
        if (url == null)
            return false;
        try
        {
            java.net.URI uri = new java.net.URI(url);
            String scheme = uri.getScheme();
            return scheme != null
                && (scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))
                && uri.getHost() != null;
        }
        catch (java.net.URISyntaxException e)
        {
            return false;
        }
    }
'''
v3 = original[:s] + b + helper + original[e:]
assert "isWebUrl(url)" in v3
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''public class HelpLauncher {

    private static final String HELP_URL = "https://desktop.jitsi.org/Documentation/";

    /**
     * Same "hand a URL to the OS browser" action, but the URL is a constant
     * baked into the program, so nothing a remote party sends can reach the
     * command that is executed.
     */
    public String helpCommandWindows() {
        return "rundll32 url.dll,FileProtocolHandler " + HELP_URL;
    }
}
'''
assert "baked into the program" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0200.")
