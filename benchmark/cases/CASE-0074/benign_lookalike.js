const path = require('path')

function pathForServerManifest(baseDir) {
  // The filename here is always the fixed literal "manifest.json" --
  // never derived from a request parameter -- so there is no traversal-
  // capable input this join could ever receive.
  return path.join(baseDir, 'manifest.json')
}

module.exports = { pathForServerManifest }
