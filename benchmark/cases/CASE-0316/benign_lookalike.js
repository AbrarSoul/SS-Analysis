'use strict';

/**
 * Display helper: turns a Windows-style file path from a build log into a
 * forward-slash path for a report. It never parses hosts or URLs and its
 * output is only printed.
 */
function toPosixDisplayPath(filePath) {
  return String(filePath).replace(/\\/g, '/');
}

function splitDisplayPath(filePath) {
  var normalized = toPosixDisplayPath(filePath)
    , index = normalized.lastIndexOf('/');

  return index === -1
    ? { dir: '', base: normalized }
    : { dir: normalized.slice(0, index), base: normalized.slice(index + 1) };
}

module.exports = { toPosixDisplayPath: toPosixDisplayPath, splitDisplayPath: splitDisplayPath };
