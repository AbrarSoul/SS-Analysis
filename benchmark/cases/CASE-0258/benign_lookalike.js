/**
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
