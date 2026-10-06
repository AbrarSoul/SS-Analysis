// Standalone example of the same shape: a linear regexp (one quantifier per
// character class, no overlap) that splits `scheme:owner/repo` for a display label.
var LABEL_RE = /^([a-z]+):([^/]+)\/([^#]+)/

module.exports = function label (spec) {
  var m = spec.match(LABEL_RE)
  return m ? m[1] + ' ' + m[2] + '/' + m[3] : null
}
