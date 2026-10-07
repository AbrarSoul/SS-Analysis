"""
Section 9 ground-truth test bundle: CASE-0018
(jenkinsci/gitlab-oauth-plugin, CVE-2019-10371/CVE-2020-2228, CWE-384/
CWE-863 -- session fixation).

Core vulnerable mechanism: doFinishLogin() sets the authenticated
principal (SecurityContextHolder.getContext().setAuthentication(auth))
immediately after a successful OAuth callback, without first invalidating
the pre-login HTTP session and issuing a fresh one. If an attacker can get
a victim to browse with a known/attacker-chosen session ID before login
(session fixation setup), that same session becomes authenticated once the
victim logs in, letting the attacker hijack it.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0018"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = (
    "        if (StringUtils.isNotBlank(accessToken)) {\n"
    "            // only set the access token if it exists.\n"
    "            GitLabAuthenticationToken auth = new GitLabAuthenticationToken(accessToken, getGitlabApiUri(), TokenType.ACCESS_TOKEN);\n"
    "            SecurityContextHolder.getContext().setAuthentication(auth);\n"
    "\n"
    "            GitlabUser self = auth.getMyself();\n"
    "            User user = User.current();\n"
    "            if (user != null) {\n"
    "                user.setFullName(self.getName());\n"
    "                // Set email from gitlab only if empty\n"
    "                if (!user.getProperty(Mailer.UserProperty.class).hasExplicitlyConfiguredAddress()) {\n"
    "                    user.addProperty(new Mailer.UserProperty(auth.getMyself().getEmail()));\n"
    "                }\n"
    "            }\n"
    "            SecurityListener.fireAuthenticated(new GitLabOAuthUserDetails(self, auth.getAuthorities()));\n"
    "        } else {\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename auth -> gitlabAuthToken throughout this block (all 5 uses). Same
# exact vulnerability: session is never invalidated/regenerated before
# setAuthentication().
renamed_block = VULNERABLE_BLOCK.replace("auth", "gitlabAuthToken")
assert "GitLabAuthenticationToken gitlabAuthToken = new GitLabAuthenticationToken" in renamed_block
renamed_source = original.replace(VULNERABLE_BLOCK, renamed_block)
assert renamed_source != original
assert renamed_source.count("gitlabAuthToken") == 5
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: wrapper-function introduction -- setAuthentication() is
# moved into a small private helper. Same exact vulnerability (still no
# session invalidation anywhere), no renaming.
structural_block = VULNERABLE_BLOCK.replace(
    "            SecurityContextHolder.getContext().setAuthentication(auth);\n",
    "            establishSecurityContext(auth);\n",
)
assert structural_block != VULNERABLE_BLOCK
structural_source = original.replace(VULNERABLE_BLOCK, structural_block)
helper_method = (
    "\n"
    "    private void establishSecurityContext(GitLabAuthenticationToken auth) {\n"
    "        SecurityContextHolder.getContext().setAuthentication(auth);\n"
    "    }\n"
)
anchor = "    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {\n"
assert anchor in structural_source
structural_source = structural_source.replace(anchor, helper_method.strip("\n") + "\n\n" + anchor, 1)
assert structural_source != original
assert "establishSecurityContext" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (session invalidated and
# regenerated before authentication is set) but via request.getSession()
# (no-arg, implicitly true) instead of the real patch's explicit
# request.getSession(true), and a different local variable name -- not
# byte-identical to the known fix.
safe_block = VULNERABLE_BLOCK.replace(
    "            GitLabAuthenticationToken auth = new GitLabAuthenticationToken(accessToken, getGitlabApiUri(), TokenType.ACCESS_TOKEN);\n"
    "            SecurityContextHolder.getContext().setAuthentication(auth);\n",
    "            GitLabAuthenticationToken auth = new GitLabAuthenticationToken(accessToken, getGitlabApiUri(), TokenType.ACCESS_TOKEN);\n"
    "\n"
    "            HttpSession existingSession = request.getSession(false);\n"
    "            if (existingSession != null) {\n"
    "                existingSession.invalidate();\n"
    "            }\n"
    "            request.getSession();\n"
    "\n"
    "            SecurityContextHolder.getContext().setAuthentication(auth);\n",
)
assert safe_block != VULNERABLE_BLOCK
safe_source = original.replace(VULNERABLE_BLOCK, safe_block)
safe_source = safe_source.replace(
    "import sun.net.util.URLUtil;\n",
    "import sun.net.util.URLUtil;\n\nimport javax.servlet.http.HttpSession;\n",
    1,
)
assert safe_source != original
assert "existingSession.invalidate();" in safe_source
assert "import javax.servlet.http.HttpSession;" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a method that also calls
# SecurityContextHolder.getContext().setAuthentication(...) -- the same
# API surface as the vulnerable line -- but for an internal background-job
# service account with no HTTP session or browser login flow involved, so
# session fixation (which requires an attacker to plant a session ID
# before a browser-based login) does not apply here.
BENIGN_ADDITION = (
    "\n"
    "    private void authenticateSystemServiceAccount(GitLabAuthenticationToken systemAuth) {\n"
    "        // Used only by internal background jobs with no HTTP session or\n"
    "        // browser-facing login flow involved -- session fixation does not\n"
    "        // apply here, unlike doFinishLogin()'s browser-based OAuth callback.\n"
    "        SecurityContextHolder.getContext().setAuthentication(systemAuth);\n"
    "    }\n"
)
anchor2 = "    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {\n"
assert anchor2 in safe_source
benign_source = safe_source.replace(anchor2, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor2, 1)
assert benign_source != safe_source
assert "authenticateSystemServiceAccount" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)

print("Wrote 4 new samples for CASE-0018.")
