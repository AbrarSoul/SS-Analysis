// Standalone example of the same shape: strip characters from a display
// label before rendering it in a terminal table header -- purely cosmetic
// cleanup of text that is never passed to a shell.
function cleanLabel(label) {
  let result = label;
  result = result.replace(/\t/g, " ");
  result = result.replace(/\n/g, " ");
  return result.trim();
}

module.exports = { cleanLabel };
