// Standalone example of the same shape: a length calculation that mirrors an
// encoder's normalisation (here for a CSV row) and is used to size a buffer
// that is fully zero-filled before writing.
function encodedLength (fields) {
  return fields.map(function (f) { return Buffer.byteLength(String(f).trim()) }).reduce(function (a, b) { return a + b + 1 }, 0)
}

function encodeRow (fields) {
  var buf = Buffer.alloc(encodedLength(fields))
  var off = 0
  fields.forEach(function (f) {
    off += buf.write(String(f).trim() + ',', off)
  })
  return buf
}

module.exports = { encodedLength: encodedLength, encodeRow: encodeRow }
