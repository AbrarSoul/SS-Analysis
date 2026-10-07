"""
Section 9 ground-truth test bundle: CASE-0217
(matrix-org/synapse, synapse/federation/federation_base.py
FederationBase._check_sigs_and_hashes, CVE-2018-16515, CWE-347 improper
verification of a cryptographic signature).

Core vulnerable mechanism: `_check_sigs_and_hashes` verifies each received
PDU's signature against `p.origin`, the server that SENT the event. The
domain of the event id (`$abc:victim.example`) and of the sender
(`@alice:victim.example`) are never checked. A malicious server
`evil.example` can therefore send `origin=evil.example, event_id=
$abc:victim.example, sender=@alice:victim.example`, sign it with its own key,
and have it accepted as an event created by victim.example / alice. The
upstream fix (`_check_sigs_on_pdus`) requires a valid signature from the
event id's domain and, when the sender's domain differs (joins/leaves), from
the sender's domain, except for invites created from a 3pid invite.

Sibling sites: this is the only call in the file that asks the keyring to
verify a PDU. `_check_sigs_and_hash` delegates to it and
`_check_sigs_and_hash_and_fetch` calls it, so one fix covers them.

Verification: each full file is imported as a module with the `synapse.*` and
`six` imports stubbed (real Twisted 26 is used) and a stub keyring whose
`verify_json_objects_for_server` returns real Deferreds that succeed only when
the requested server is one of the servers that signed that event. Two events
are checked: an honest one (origin = event-id domain = sender domain = a.example,
signed by a.example) and a forged one (origin evil.example, event id and sender on
victim.example, signed only by evil.example).

Every variant is the FULL real file. _check_sigs_and_hashes is called by name
from the class's own methods, so its name and signature are kept; the renamed
variant renames its locals and inner functions.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0217"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


s = original.index("    def _check_sigs_and_hashes(self, pdus):")
e = original.index("\n\ndef event_from_pdu_json")
METHOD = original[s:e]

# --- Variant 1: renamed vulnerable variant ---
doc_end = METHOD.index('"""', METHOD.index('"""') + 3) + 3   # leave the docstring text alone
m1_head, m1 = METHOD[:doc_end], METHOD[doc_end:]
for a, b in (("redacted_pdus", "pruned_pdus"), ("deferreds", "sig_checks"), ("ctx", "log_ctx"),
             ("redacted", "pruned"), ("callback", "on_valid"), ("errback", "on_invalid")):
    assert a in m1
    m1 = m1.replace(a, b)
m1 = m1_head + m1
# addCallbacks is a Twisted method name, and callbackArgs/errbackArgs are its keywords
m1 = m1.replace("add" + "on_valid" + "s", "addCallbacks").replace("on_valid" + "Args", "callbackArgs").replace("on_invalid" + "Args", "errbackArgs")
assert "addCallbacks(" in m1 and "callbackArgs=" in m1 and "errbackArgs=" in m1
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + m1 + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
REQ = '''        deferreds = self.keyring.verify_json_objects_for_server([
            (p.origin, p.get_pdu_json())
            for p in redacted_pdus
        ])
'''
v2 = swap(original, REQ, '''        deferreds = self._verify_signing_servers(redacted_pdus)
''')
v2 = swap(v2, "    def _check_sigs_and_hashes(self, pdus):", '''    def _verify_signing_servers(self, redacted_pdus):
        requests = []
        for p in redacted_pdus:
            requests.append((p.origin, p.get_pdu_json()))
        return self.keyring.verify_json_objects_for_server(requests)

    def _check_sigs_and_hashes(self, pdus):''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# One flat keyring request covering every required signer of every PDU, then
# a per-PDU DeferredList; upstream builds two keyring requests and merges.
v3 = swap(original, "from twisted.internet import defer\n", "from twisted.internet import defer\nfrom twisted.internet.defer import DeferredList\n")
v3 = swap(v3, "from synapse.api.constants import MAX_DEPTH\n", "from synapse.api.constants import MAX_DEPTH, EventTypes, Membership\n")
v3 = swap(v3, "from synapse.http.servlet import assert_params_in_dict\n", "from synapse.http.servlet import assert_params_in_dict\nfrom synapse.types import get_domain_from_id\n")
v3 = swap(v3, REQ, '''        # every PDU must be signed by the domain of its event id and, when the sender
        # is on another domain, by the sender's domain (3pid invites are exempt)
        requests = []
        owners = []
        for idx, p in enumerate(redacted_pdus):
            for domain in _required_signers(pdus[idx]):
                requests.append((domain, p.get_pdu_json()))
                owners.append(idx)
        checks = self.keyring.verify_json_objects_for_server(requests)
        per_pdu = [[] for _ in redacted_pdus]
        for idx, check in zip(owners, checks):
            per_pdu[idx].append(check)
        deferreds = [
            group[0] if len(group) == 1
            else DeferredList(group, fireOnOneErrback=True, consumeErrors=True)
            for group in per_pdu
        ]
''')
v3 = swap(v3, "\n\ndef event_from_pdu_json", '''

def _required_signers(pdu):
    domains = [get_domain_from_id(pdu.event_id)]
    sender_domain = get_domain_from_id(pdu.sender)
    is_3pid_invite = (
        pdu.type == EventTypes.Member
        and pdu.membership == Membership.INVITE
        and "third_party_invite" in pdu.content
    )
    if sender_domain != domains[0] and not is_3pid_invite:
        domains.append(sender_domain)
    return domains


def event_from_pdu_json''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: choose which servers must vouch for a
record, for an internal audit report where nothing is trusted because of the
answer."""


def reviewers_needed(record):
    reviewers = [record["owner_team"]]
    if record["requested_by_team"] != record["owner_team"]:
        reviewers.append(record["requested_by_team"])
    return reviewers
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
