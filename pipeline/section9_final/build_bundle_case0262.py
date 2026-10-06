"""
Section 9 ground-truth test bundle: CASE-0262
(poezio/slixmpp, slixmpp/plugins/xep_0280/carbons.py XEP_0280
_handle_carbon_received/_handle_carbon_sent, CVE-2017-5591, CWE-20/CWE-346
improper origin validation of an XMPP Message Carbons stanza).

Core vulnerable mechanism: XEP-0280 Message Carbons lets a server forward a
copy of every message the account sends/receives to all of that account's
other connected clients, wrapped in a `<received>`/`<sent>` carbon element.
`_handle_carbon_received`/`_handle_carbon_sent` fire whenever an incoming
`<message>` stanza matches the `message/carbon_received` (or `_sent`) XPath
-- but XMPP message routing does not restrict WHO can send a client a
`<message>` stanza carrying such a child; per the spec, carbons are only
trustworthy when the enclosing `<message>`'s `from` is the user's own bare
JID (the account's server, on the account's behalf), since that is the one
sender who cannot be impersonated without compromising the account. Both
handlers unconditionally call `self.xmpp.event(...)`, so ANY contact (or
anyone who gets a stanza routed to the client, e.g. via a MUC or a federated
server) can forge a `<message><received><forwarded><message from="victim"
to="target">...` carbon and have the client's `carbon_received`/`carbon_sent`
event fire exactly as if the account's own server had sent it -- letting an
attacker inject spoofed "this is a message the account itself sent/received"
events, which client code (chat logs, notification suppression, message
de-duplication) typically trusts implicitly. The upstream fix adds `if
msg['from'].bare == self.xmpp.boundjid.bare:` before firing either event, so
only a stanza whose sender is the account's own bare JID is trusted.

Sibling sites: `_handle_carbon_received` and `_handle_carbon_sent` are the
only two carbon-stanza handlers in the file, and both have the identical
unchecked-origin defect; the safe variant fixes both, matching the real
patch.

Verification: each full file is imported as the real, unmodified module
(`import slixmpp` alongside it so `slixmpp.stanza.Message`/
`slixmpp.xmlstream.JID` are the REAL library types) with only `self.xmpp`
stood in as a minimal object exposing `boundjid` (a real `JID` for
`user@example.com`) and an `event(name, msg)` recorder; `plugin_init` is not
called (no live XML stream/plugin manager needed). `_handle_carbon_received`
is invoked with a real `Message` stanza whose `from` is set to a spoofed
third party (`mallory@evil.example/res`), then again with `from` set to the
account's own bare JID at a different resource (`user@example.com/other`,
the legitimate case: the account's server relays carbons from the bare JID,
often a different resource than the receiving client). The recorder shows
whether `carbon_received` fired for the spoofed sender.

Every variant is the FULL real file. `_handle_carbon_received`/
`_handle_carbon_sent` are registered by name as `Callback` handlers in
`plugin_init` and dispatch a named event other code subscribes to, so their
names and signatures are kept; the renamed variant renames the local origin
JID it compares against.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0262"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


HANDLERS = """    def _handle_carbon_received(self, msg):
        self.xmpp.event('carbon_received', msg)

    def _handle_carbon_sent(self, msg):
        self.xmpp.event('carbon_sent', msg)
"""
assert original.count(HANDLERS) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, HANDLERS, """    def _handle_carbon_received(self, stanza):
        self.xmpp.event('carbon_received', stanza)

    def _handle_carbon_sent(self, stanza):
        self.xmpp.event('carbon_sent', stanza)
""")
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, HANDLERS, """    def _dispatch_carbon(self, event_name, msg):
        self.xmpp.event(event_name, msg)

    def _handle_carbon_received(self, msg):
        self._dispatch_carbon('carbon_received', msg)

    def _handle_carbon_sent(self, msg):
        self._dispatch_carbon('carbon_sent', msg)
""")
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, HANDLERS, """    def _is_from_account(self, msg):
        account_bare = self.xmpp.boundjid.bare
        sender_bare = msg['from'].bare
        return sender_bare == account_bare

    def _handle_carbon_received(self, msg):
        if not self._is_from_account(msg):
            return
        self.xmpp.event('carbon_received', msg)

    def _handle_carbon_sent(self, msg):
        if not self._is_from_account(msg):
            return
        self.xmpp.event('carbon_sent', msg)
""")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""
Standalone example of the same shape: filter which of the ACCOUNT'S OWN
locally-queued reminders get dispatched as desktop notifications by matching
a label the account itself set (never data a remote party controls), so a
label mismatch is a UX filter, not a security boundary.
"""


class ReminderNotifier:

    def __init__(self, active_label):
        self.active_label = active_label
        self.fired = []

    def _handle_reminder_due(self, reminder):
        if reminder['label'] == self.active_label:
            self.fired.append(reminder)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
