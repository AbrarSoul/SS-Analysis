// Standalone example of the same shape: build a grid cell from a value the
// application itself computed (a row number), never from user-controlled
// text, so unescaped interpolation has nothing hostile to carry.
function rowNumberCell(index) {
	return '<td class="num">' + (index + 1) + '</td>';
}

module.exports = rowNumberCell;
