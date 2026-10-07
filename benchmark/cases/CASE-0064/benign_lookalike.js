const BUILT_IN_PLACEHOLDERS = { amp: "&", lt: "<", gt: ">" };

function compileBuiltInPlaceholderRegexes() {
  // BUILT_IN_PLACEHOLDERS is a fixed object literal defined above, in
  // this module's own source -- never derived from caller input, so its
  // keys can never contain attacker-influenced regex metacharacters.
  const compiled = {};
  const keys = Object.keys(BUILT_IN_PLACEHOLDERS);
  for (let i = 0; i < keys.length; i++) {
    const name = keys[i];
    compiled[name] = new RegExp("&" + name + ";", "g");
  }
  return compiled;
}

module.exports = { compileBuiltInPlaceholderRegexes };
