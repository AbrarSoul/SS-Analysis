// Standalone example of the same shape: default an unspecified reconnection
// delay option to null (meaning "use the library default"), a tuning knob
// with no security consequence.
function readOptions(opts) {
  opts = opts || {};
  return {
    reconnectionDelay: opts.reconnectionDelay === undefined ? null : opts.reconnectionDelay
  };
}

module.exports = readOptions;
