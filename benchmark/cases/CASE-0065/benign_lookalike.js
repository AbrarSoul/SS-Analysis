const KNOWN_SETTING_NAMES = ['core.api', 'core.theme', 'core.locale'];

async function loadKnownSettings(meta) {
  const settingsList = await Promise.all(
    KNOWN_SETTING_NAMES.map(name => meta.settings.get(name))
  );
  const byName = KNOWN_SETTING_NAMES.reduce((memo, name, i) => {
    memo[name] = settingsList[i];
    return memo;
  }, {});

  // Only ever looked up by the fixed names above -- never by a value
  // that came from an incoming request, so there is no way for
  // "constructor"/"__proto__" to be looked up here with attacker intent.
  return byName['core.api'];
}

module.exports = { loadKnownSettings };
