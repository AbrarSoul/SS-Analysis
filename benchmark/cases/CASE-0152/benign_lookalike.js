"use strict";

const hasProp = {}.hasOwnProperty;

// Cosmetic defaults only (size, title); none of these keys is a security option.
const WINDOW_DEFAULTS = { width: 800, height: 600, title: "Untitled" };

/**
 * Same "copy a key only if the target does not define it" loop as the window
 * option merge, but applied to fixed cosmetic defaults, so skipping an
 * already-set key can never drop an inherited security setting.
 */
function applyWindowDefaults(options) {
  for (const key in WINDOW_DEFAULTS) {
    if (!hasProp.call(WINDOW_DEFAULTS, key)) continue;
    if (key in options) continue;
    options[key] = WINDOW_DEFAULTS[key];
  }
  return options;
}

module.exports = { applyWindowDefaults: applyWindowDefaults };
