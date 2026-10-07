// Standalone example of the same shape: build a small HTML snippet from a
// FIXED, hard-coded set of themes (never user-supplied text), so nothing
// attacker-controlled is interpolated into markup.
const THEMES = { light: "#ffffff", dark: "#111111" } as const;

export function themedBadge(theme: keyof typeof THEMES) {
  return `<span class="badge" style="background:${THEMES[theme]}">note</span>`;
}
