// Standalone example of the same shape: writing settings to a file, but as
// JSON.stringify output, so a value can never start a new entry.
const fs = require("fs");
const path = require("path");

function dumpSettings(settings, dir) {
  const out = {};
  for (const [key, value] of Object.entries(settings)) {
    if (value) out[key] = String(value);
  }
  fs.writeFileSync(path.join(dir, "settings.json"), JSON.stringify(out, null, 2), "utf8");
  return true;
}

module.exports = { dumpSettings };
