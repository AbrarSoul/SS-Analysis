"""
Section 9 ground-truth test bundle: CASE-0293
(spring-projects/spring-framework, spring-messaging/src/main/java/org/
springframework/messaging/simp/broker/DefaultSubscriptionRegistry.java
filterSubscriptions + SimpMessageHeaderPropertyAccessor, CVE-2018-1270,
CWE-94/CWE-358 expression-language injection).

Core vulnerable mechanism: with the STOMP `selector` header a subscriber
gives the broker a SpEL expression that is later evaluated against every
message published to the destination. The vulnerable code evaluates it in
a `StandardEvaluationContext` -- the full-power SpEL context: it allows
type references (`T(java.lang.Runtime)`), constructors, and arbitrary
method calls. Any client that can SUBSCRIBE (typically an unauthenticated or
low-privileged browser over WebSocket) can therefore run arbitrary code in
the server JVM, e.g. `selector: T(java.lang.Runtime).getRuntime().exec(...)`.
The upstream fix evaluates in a read-only, restricted `SimpleEvaluationContext`
built once with only the custom message-header property accessor, evaluating
against the message as root object (the accessor gains a `Message` -> `headers`
step so expressions like `headers.foo == 'bar'` keep working).

Sibling sites: `filterSubscriptions` is the only evaluation site; the
property-accessor changes are the supporting part of the same fix.

Verification: each FULL file is compiled with javac (JDK 26) as a
replacement for `DefaultSubscriptionRegistry` against the REAL
`spring-messaging`/`spring-core`/`spring-expression`/`spring-beans`/
`spring-context` 4.3.15.RELEASE jars from Maven Central (the class the file
belongs to; the version this code line comes from), and driven through the
public API: a real STOMP SUBSCRIBE message carrying a `selector` header is
registered, then a real message to that destination is looked up with
`findSubscriptions`. The malicious selector
`T(java.lang.System).setProperty('cs.pwned','yes') == 'zzz'` executes a real
JVM side effect (a system property write) if the expression is evaluated
with full SpEL power; the property is checked afterwards. A benign selector
`headers.destination == '/topic/x'` must still match the subscription in every
variant (the fix must not break legitimate selectors).

Every variant is the FULL real file. The class and its public API are used by
name across Spring's STOMP broker, so they are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0293"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


DECL = "\t\tEvaluationContext context = null;\n"
CTX = '''				if (context == null) {
					context = new StandardEvaluationContext(message);
					context.getPropertyAccessors().add(new SimpMessageHeaderPropertyAccessor());
				}
				try {
					if (expression.getValue(context, boolean.class)) {
'''
assert original.count(DECL) == 1 and original.count(CTX) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, DECL, "\t\tEvaluationContext evalContext = null;\n")
v1 = swap(v1, CTX, '''				if (evalContext == null) {
					evalContext = new StandardEvaluationContext(message);
					evalContext.getPropertyAccessors().add(new SimpMessageHeaderPropertyAccessor());
				}
				try {
					if (expression.getValue(evalContext, boolean.class)) {
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CTX, '''				if (context == null) {
					context = createSelectorContext(message);
				}
				try {
					if (expression.getValue(context, boolean.class)) {
''')
v2 = swap(v2, "\tprivate MultiValueMap<String, String> filterSubscriptions(", '''	private static EvaluationContext createSelectorContext(Message<?> message) {
		StandardEvaluationContext ctx = new StandardEvaluationContext(message);
		ctx.getPropertyAccessors().add(new SimpMessageHeaderPropertyAccessor());
		return ctx;
	}

	private MultiValueMap<String, String> filterSubscriptions(''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, context built by a factory) ---
OLD = '''	private static EvaluationContext messageEvalContext =
			SimpleEvaluationContext.forPropertyAccessors(new SimpMessageHeaderPropertyAccessor()).build();
'''
assert patched.count(OLD) == 1
v3 = swap(patched, OLD, '''	private static EvaluationContext messageEvalContext = restrictedSelectorContext();

	private static EvaluationContext restrictedSelectorContext() {
		return SimpleEvaluationContext.forPropertyAccessors(new SimpMessageHeaderPropertyAccessor()).build();
	}
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package org.springframework.messaging.simp.broker;

/**
 * Standalone example of the same shape: match a destination against a fixed
 * comparison operator chosen from an enum (never a caller-supplied
 * expression), so nothing is interpreted as code.
 */
class DestinationMatcher {

    enum Op { EQUALS, PREFIX }

    static boolean matches(Op op, String destination, String pattern) {
        return op == Op.EQUALS ? destination.equals(pattern) : destination.startsWith(pattern);
    }
}
''')
