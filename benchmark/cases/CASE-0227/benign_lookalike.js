// Standalone example of the same shape: tidy a display title by trimming
// and collapsing runs of whitespace; the value is only shown in a heading and
// never used as a path.
function tidyTitle(title = "") {
  const result = title.trim().replace(/\s+/g, " ").trim();
  if (["", "-"].includes(result)) throw new Error("Invalid title.");
  return result;
}

module.exports = { tidyTitle };
