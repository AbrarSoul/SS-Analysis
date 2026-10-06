// Standalone example of the same shape: rewrap entries of a list, but always
// into a freshly allocated array, so the caller's original array (whichever realm
// it came from) is never written into.
function rewrapAll(list, wrap) {
	const out = [];
	for (let i = 0; i < list.length; i++) {
		out[i] = wrap(list[i]);
	}
	return out;
}

module.exports = { rewrapAll };
