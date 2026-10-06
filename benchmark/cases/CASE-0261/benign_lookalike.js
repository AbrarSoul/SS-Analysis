/**
 * Standalone example of the same shape: read an optional, nested field off a
 * value this module itself constructs (a local settings object with a fixed,
 * known shape), never data an external server response controls, so a
 * missing intermediate field is a static, unit-testable non-issue rather
 * than something to guard defensively.
 */
const DEFAULT_THEME = { colors: { accent: '#0b5fff' } };

export function getAccentColor(theme) {
  const merged = { ...DEFAULT_THEME, ...theme };
  return merged.colors.accent;
}
