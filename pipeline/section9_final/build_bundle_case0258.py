"""
Section 9 ground-truth test bundle: CASE-0258
(pkp/pkp-lib, js/controllers/grid/users/reviewer/
AdvancedReviewerSearchHandler.js AdvancedReviewerSearchHandler,
CVE-2023-5890, CWE-79 stored cross-site scripting).

Core vulnerable mechanism: after an editor picks a reviewer from the advanced
search results, the handler shows the chosen name with
`$('[id^="selectedReviewerName"]').html(reviewer.fullName)`. `reviewer.fullName`
is the reviewer's own profile name, a value that OJS/OMP account holders set
for themselves, so a reviewer whose name contains
`<img src=x onerror=alert(document.cookie)>` gets that markup parsed and
executed as HTML in the editor's browser the moment they select that reviewer
in the search results, with the editor's session. The upstream fix uses
`.text(reviewer.fullName)`, which sets the element's text content instead of
parsing it as HTML.

Sibling sites: this is the only place in the file that inserts reviewer data
into the DOM.

Verification: the whole IIFE is loaded (as the real file) into a Node context
with the REAL `jquery` package running over a REAL `jsdom` document (`global.window`/
`global.document` set before requiring `jquery`, as the jQuery UMD wrapper
requires), and stand-ins for `pkp.eventBus`, `pkp.classes.Handler`/`Helper`
that only record the `selected:reviewer` callback and let `inherits` and
`this.parent`/`this.bind` no-op. The `selected:reviewer` event is fired with a
reviewer whose `fullName` is an `<img onerror=...>` payload; the DOM element's
resulting markup is inspected for a real, parsed `<img>` element versus escaped
text.

Every variant is the FULL real file. The handler is a jQuery-plugin-style
constructor referenced by name from PHP-rendered templates
(`$.pkp.controllers.grid.users.reviewer.AdvancedReviewerSearchHandler`), so it
and its prototype methods keep their names; the renamed variant renames the
event-callback's parameter and its own locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0258"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


HANDLER = """\t\tpkp.eventBus.$on('selected:reviewer', function(reviewer) {
\t\t\t$('#reviewerId').val(reviewer.id);
\t\t\t$('[id^="selectedReviewerName"]').html(reviewer.fullName);
\t\t\t$('#searchGridAndButton').hide();
\t\t\t$('#regularReviewerForm').show();
\t\t});
"""
assert original.count(HANDLER) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, HANDLER, """\t\tpkp.eventBus.$on('selected:reviewer', function(selectedReviewer) {
\t\t\t$('#reviewerId').val(selectedReviewer.id);
\t\t\t$('[id^="selectedReviewerName"]').html(selectedReviewer.fullName);
\t\t\t$('#searchGridAndButton').hide();
\t\t\t$('#regularReviewerForm').show();
\t\t});
""")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, HANDLER, """\t\tpkp.eventBus.$on('selected:reviewer', this.showSelectedReviewer_.bind(this));
""")
v2 = swap(v2, "\t\tthis.bind('refreshForm', this.handleRefresh_);\n\t};", """\t\tthis.bind('refreshForm', this.handleRefresh_);
\t};

\t/**
\t * Show the reviewer chosen from the advanced search results.
\t * @private
\t * @param {Object} reviewer The selected reviewer data.
\t */
\t$.pkp.controllers.grid.users.reviewer.AdvancedReviewerSearchHandler.prototype.
\t\t\tshowSelectedReviewer_ = function(reviewer) {
\t\t$('#reviewerId').val(reviewer.id);
\t\t$('[id^="selectedReviewerName"]').html(reviewer.fullName);
\t\t$('#searchGridAndButton').hide();
\t\t$('#regularReviewerForm').show();
\t};""")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, HANDLER, """\t\tpkp.eventBus.$on('selected:reviewer', function(reviewer) {
\t\t\t$('#reviewerId').val(reviewer.id);
\t\t\t// The reviewer's own profile name is untrusted; never parse it as HTML.
\t\t\tvar $nameEl = $('[id^="selectedReviewerName"]');
\t\t\t$nameEl.empty();
\t\t\t$nameEl.append(document.createTextNode(reviewer.fullName));
\t\t\t$('#searchGridAndButton').hide();
\t\t\t$('#regularReviewerForm').show();
\t\t});
""")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = """/**
 * Standalone example of the same shape: render a status badge whose text is
 * one of a small, fixed set of labels the SERVER chose (never the reviewer's
 * own profile text), so .html() is not a risk here.
 */
(function($) {
	$.pkp.setStatusBadge = function(status) {
		var labels = {approved: 'Approved', pending: 'Pending', rejected: 'Rejected'};
		$('#reviewStatus').html(labels[status] || 'Unknown');
	};
}(jQuery));
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
