// Standalone example of the same shape: generate a small formatter function
// with new Function from a FIXED, application-owned list of column names
// (never from request data), so the compiled source is fully trusted.
var COLUMNS = ['id', 'name', 'email'];

var formatRow = new Function('row', 'return ' + COLUMNS.map(function (c) { return 'row.' + c; }).join(" + ',' + "));

module.exports = formatRow;
