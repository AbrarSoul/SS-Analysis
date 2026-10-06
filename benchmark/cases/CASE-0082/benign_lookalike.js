/* Same nested-quantifier shape as the vulnerable email regex, but the
 * input length is capped at 10 characters before matching, so the worst
 * case is bounded and negligible; it is not a denial-of-service vector. */
var codes = {};

codes.isShortCode = function(str) {
	if (typeof str !== 'string' || str.length > 10) {
		return false;
	}
	return (/^\w+([.-]?\w+)*$/.test(str));
};
