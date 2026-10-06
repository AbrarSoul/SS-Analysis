// Standalone example of the same shape: normalize a display label by
// stripping leading/trailing whitespace before storing it, purely so the
// UI doesn't show stray padding -- the label is only ever rendered as
// text, never used to build executable source, so untrimmed whitespace is
// a cosmetic issue, not a security one.
function DisplayLabel(text) {
    this.text = String(text).trim();
}

module.exports = DisplayLabel;
