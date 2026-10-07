"""
Section 9 ground-truth test bundle: CASE-0229
(mitreid-connect/OpenID-Connect-Java-Spring-Server,
openid-connect-server/.../oauth2/web/OAuthConfirmationController.java
confimAccess, CVE-2021-26715, CWE-1321 / CWE-918 improperly controlled
modification of an object through data binding).

Core vulnerable mechanism: the consent-page handler declares its stored
authorisation request as `@ModelAttribute("authorizationRequest")
AuthorizationRequest authRequest`. With `@SessionAttributes("authorizationRequest")`
on the class, Spring loads the pending request from the session and then
BINDS THE HTTP REQUEST PARAMETERS ONTO IT (measured: with nothing stored in the
session the same handler fails with HttpSessionRequiredException instead). A user who opens
`/oauth/confirm_access?redirectUri=https://evil.example/cb&clientId=...&scope=...`
therefore changes the pending request's redirect URI, client id and scopes before
the consent page is rendered and approved, so the code or token is sent to the
attacker's URL. The upstream fix removes the `@ModelAttribute` parameter and reads
the request from the model: `(AuthorizationRequest) model.get("authorizationRequest")`.

Measured caveat, kept in the manifest notes: the upstream version has no null check,
so when no request is stored in the session it fails with a NullPointerException at
`authRequest.getExtensions()` (the vulnerable form fails earlier, with Spring's
HttpSessionRequiredException); the safe variant answers 400 instead.

Sibling sites: `confimAccess` is the only handler in the file that declares this
binding; other methods do not take an AuthorizationRequest parameter.

Verification: the handler's annotations and signature (plus, for the fixed forms, the
first lines that read the request from the model) are extracted from each full file into
a controller class compiled with javac against the REAL Spring MVC / Spring Test 4.3.30
and spring-security-oauth2 2.3.8 jars, with the same class-level
`@SessionAttributes("authorizationRequest")`; the rest of the handler body is replaced by
stub code that reports what the handler saw. Standalone MockMvc requests are made with a
pending request in the session (client good-client, redirect https://good.example/cb) and the
extra parameters `redirectUri=https://evil.example/cb`, and once with no session request.

Every variant is the FULL real file. The handler is mapped by @RequestMapping (not called by name); the renamed
variant renames its parameter and a local.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0229"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


SIG = '''	public String confimAccess(Map<String, Object> model, @ModelAttribute("authorizationRequest") AuthorizationRequest authRequest,
			Principal p) {
'''
assert original.count(SIG) == 1
s = original.index(SIG)
e = original.index("\n\t}\n", s) + 4
BODY = original[s:e]

# --- Variant 1: renamed vulnerable variant ---
import re
b1 = BODY
b1 = re.sub(r"\bmodel\b", "viewModel", b1)
b1 = re.sub(r"\bauthRequest\b", "pendingRequest", b1)
assert 'viewModel.put("auth_request", pendingRequest);' in b1 and '@ModelAttribute("authorizationRequest") AuthorizationRequest pendingRequest' in b1
(CASE_DIR / "variant_vulnerable_01.java").write_text(original[:s] + b1 + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
PROMPT = '''		String prompt = (String)authRequest.getExtensions().get(PROMPT);
		List<String> prompts = Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));
'''
assert original.count(PROMPT) == 1
v2 = swap(original, PROMPT, '''		List<String> prompts = promptsOf(authRequest);
''')
v2 = swap(v2, "	@PreAuthorize(\"hasRole('ROLE_USER')\")\n	@RequestMapping(\"/oauth/confirm_access\")", '''	private List<String> promptsOf(AuthorizationRequest request) {
		String prompt = (String)request.getExtensions().get(PROMPT);
		return Splitter.on(PROMPT_SEPARATOR).splitToList(Strings.nullToEmpty(prompt));
	}

	@PreAuthorize("hasRole('ROLE_USER')")
	@RequestMapping("/oauth/confirm_access")''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, SIG, '''	public String confirmAccess(Map<String, Object> model, Principal p) {

		// The pending request comes from the session-backed model, never from request parameters.
		AuthorizationRequest authRequest = (AuthorizationRequest) model.get("authorizationRequest");
		if (authRequest == null) {
			model.put(HttpCodeView.CODE, HttpStatus.BAD_REQUEST);
			return HttpCodeView.VIEWNAME;
		}
''')
v3 = swap(v3, "import org.springframework.web.bind.annotation.ModelAttribute;\n", "")
(CASE_DIR / "variant_safe_01.java").write_text(v3)

BENIGN = '''package org.mitre.oauth2.web;

import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Standalone example of the same shape: a form-backed page whose object is a
 * plain display preferences bean that is SUPPOSED to be filled from request
 * parameters; no security decision depends on any of its fields.
 */
@Controller
public class DisplayPreferencesController {

	public static class DisplayPreferences {
		private String theme = "light";
		public String getTheme() { return theme; }
		public void setTheme(String theme) { this.theme = theme; }
	}

	@RequestMapping("/preferences")
	public String show(Map<String, Object> model, @ModelAttribute("prefs") DisplayPreferences prefs) {
		model.put("theme", prefs.getTheme());
		return "preferences";
	}
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN)
