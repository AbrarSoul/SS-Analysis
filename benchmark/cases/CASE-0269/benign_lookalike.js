// Standalone example of the same shape: validate that a locally-configured
// theme name matches a small allow-list before using it to pick a CSS
// class, purely so a typo in local config fails loudly instead of
// silently rendering unstyled -- theme names are never attacker input and
// are never spliced into executable code, so this is a config sanity
// check, not a security boundary.
var ALLOWED_THEMES = ['light', 'dark', 'high-contrast'];

function assertKnownTheme(themeName) {
  if (ALLOWED_THEMES.indexOf(themeName) === -1) {
    throw new Error('Unknown theme: ' + themeName);
  }
}

module.exports = { assertKnownTheme };
