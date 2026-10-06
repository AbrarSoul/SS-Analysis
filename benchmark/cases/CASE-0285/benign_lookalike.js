// Standalone example of the same shape: choose a display quoting style per
// output format for a label shown in a CLI table (not SQL, never executed).
function quoteLabel(label, format) {
  if (format === "markdown") {
    return "`" + label.replace(/`/g, "'") + "`";
  }
  return '"' + label.replace(/"/g, '\\"') + '"';
}

module.exports = { quoteLabel };
