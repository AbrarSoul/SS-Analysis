"""
Section 9 ground-truth test bundle: CASE-0020
(spring-projects/spring-security-samples, CVE-2023-34035, CWE-863 --
incorrect authorization / Spring Security MVC path-matching bypass).

Core vulnerable mechanism: securityFilterChain() authorizes requests using
plain ant-pattern strings (.requestMatchers("/login", "/resources/**")).
When the DispatcherServlet is mapped in certain non-default ways, Spring
MVC can resolve a request to a handler via a path Spring Security's plain
ant matcher does not recognize as matching, letting a crafted request
bypass the intended authorization rule. The real fix uses
MvcRequestMatcher (mvc.pattern(...)), which matches using the same
resolution Spring MVC itself uses.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0020"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = (
    "\t@Bean\n"
    "\tpublic SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {\n"
    "\t\t// @formatter:off\n"
    "\t\thttp\n"
    "\t\t\t\t.authorizeHttpRequests((authorize) -> authorize\n"
    "\t\t\t\t\t\t.requestMatchers(\"/login\", \"/resources/**\").permitAll()\n"
    "\t\t\t\t\t\t.anyRequest().authenticated()\n"
    "\t\t\t\t)\n"
    "\t\t\t\t.jee((jee) -> jee.mappableRoles(\"USER\", \"ADMIN\"));\n"
    "\t\t// @formatter:on\n"
    "\t\treturn http.build();\n"
    "\t}\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename securityFilterChain -> configureSecurityFilterChain, parameter
# http -> httpSecurity. Same exact vulnerability: still plain ant-pattern
# requestMatchers with no MvcRequestMatcher.
RENAMED_BLOCK = (
    "\t@Bean\n"
    "\tpublic SecurityFilterChain configureSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {\n"
    "\t\t// @formatter:off\n"
    "\t\thttpSecurity\n"
    "\t\t\t\t.authorizeHttpRequests((authorize) -> authorize\n"
    "\t\t\t\t\t\t.requestMatchers(\"/login\", \"/resources/**\").permitAll()\n"
    "\t\t\t\t\t\t.anyRequest().authenticated()\n"
    "\t\t\t\t)\n"
    "\t\t\t\t.jee((jee) -> jee.mappableRoles(\"USER\", \"ADMIN\"));\n"
    "\t\t// @formatter:on\n"
    "\t\treturn httpSecurity.build();\n"
    "\t}\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
assert renamed_source != original
assert "configureSecurityFilterChain" in renamed_source
assert "httpSecurity" in renamed_source
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable -- the ant-pattern
# strings are extracted into a named array. Same exact vulnerability
# (still no MvcRequestMatcher), no renaming.
STRUCTURAL_BLOCK = (
    "\t@Bean\n"
    "\tpublic SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {\n"
    "\t\t// @formatter:off\n"
    "\t\tString[] publicPaths = { \"/login\", \"/resources/**\" };\n"
    "\t\thttp\n"
    "\t\t\t\t.authorizeHttpRequests((authorize) -> authorize\n"
    "\t\t\t\t\t\t.requestMatchers(publicPaths).permitAll()\n"
    "\t\t\t\t\t\t.anyRequest().authenticated()\n"
    "\t\t\t\t)\n"
    "\t\t\t\t.jee((jee) -> jee.mappableRoles(\"USER\", \"ADMIN\"));\n"
    "\t\t// @formatter:on\n"
    "\t\treturn http.build();\n"
    "\t}\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "String[] publicPaths" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (MVC-aware path matching) but
# constructs MvcRequestMatcher.Builder INLINE from an injected
# HandlerMappingIntrospector, instead of the real patch's separate
# @Scope("prototype") @Bean MvcRequestMatcher.Builder mvc(...) definition
# -- materially different structure, not byte-identical to the known fix.
SAFE_BLOCK = (
    "\t@Bean\n"
    "\tpublic SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {\n"
    "\t\t// @formatter:off\n"
    "\t\tMvcRequestMatcher.Builder mvc = new MvcRequestMatcher.Builder(introspector);\n"
    "\t\thttp\n"
    "\t\t\t\t.authorizeHttpRequests((authorize) -> authorize\n"
    "\t\t\t\t\t\t.requestMatchers(mvc.pattern(\"/login\"), mvc.pattern(\"/resources/**\")).permitAll()\n"
    "\t\t\t\t\t\t.anyRequest().authenticated()\n"
    "\t\t\t\t)\n"
    "\t\t\t\t.jee((jee) -> jee.mappableRoles(\"USER\", \"ADMIN\"));\n"
    "\t\t// @formatter:on\n"
    "\t\treturn http.build();\n"
    "\t}\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
safe_source = safe_source.replace(
    "import org.springframework.security.web.SecurityFilterChain;\n",
    "import org.springframework.security.web.SecurityFilterChain;\n"
    "import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;\n"
    "import org.springframework.web.servlet.handler.HandlerMappingIntrospector;\n",
    1,
)
assert safe_source != original
assert "new MvcRequestMatcher.Builder(introspector)" in safe_source
assert 'requestMatchers("/login", "/resources/**")' not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a WebSecurityCustomizer
# bean that also calls .requestMatchers(...) with plain ant-pattern
# strings -- the same superficial API surface as the vulnerable line --
# but via web.ignoring(), which excludes these paths from the security
# filter chain entirely (no authorization decision is made for them at
# all), so the MVC-path-mapping bypass this CVE describes, which requires
# an authorization rule to be circumvented, does not apply.
BENIGN_ADDITION = (
    "\n"
    "\t@Bean\n"
    "\tpublic WebSecurityCustomizer webSecurityCustomizer() {\n"
    "\t\t// Paths ignored here are excluded from the security filter chain\n"
    "\t\t// entirely -- no authorization decision is made for them at all --\n"
    "\t\t// so the MVC-path-mapping ambiguity that enables CVE-2023-34035's\n"
    "\t\t// authorization bypass does not apply, unlike the permitAll() rule\n"
    "\t\t// above.\n"
    "\t\treturn (web) -> web.ignoring().requestMatchers(\"/css/**\", \"/js/**\");\n"
    "\t}\n"
)
anchor = "\t@Bean\n\tpublic SecurityFilterChain securityFilterChain(HttpSecurity http, HandlerMappingIntrospector introspector) throws Exception {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
benign_source = benign_source.replace(
    "import org.springframework.context.annotation.Configuration;\n",
    "import org.springframework.context.annotation.Configuration;\n"
    "import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;\n",
    1,
)
assert benign_source != safe_source
assert "webSecurityCustomizer" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)

print("Wrote 4 new samples for CASE-0020.")
