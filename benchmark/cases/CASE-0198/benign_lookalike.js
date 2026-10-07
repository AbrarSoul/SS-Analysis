"use strict";

var PALETTE = ['#000000', '#ffffff', '#ff0000', '#00ff00', '#0000ff'];

/**
 * Same "apply a colour then close the dialog" shape as the dialog handler,
 * but the colour comes from a FIXED palette by index, never from typed text,
 * so there is nothing to validate or inject.
 */
function applyPaletteColor(index, applyFunction, hideDialog) {
  var color = PALETTE[index];
  if (color != null) {
    applyFunction(color);
  }
  hideDialog();
}

module.exports = { applyPaletteColor: applyPaletteColor };
