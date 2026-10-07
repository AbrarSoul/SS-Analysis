// Standalone example of the same shape: a UI preference cookie that carries
// no credential, so a site-wide path and a long lifetime are fine.
export function rememberTheme(theme: 'light' | 'dark') {
	document.cookie = `theme=${theme}; path=/; max-age=31536000; SameSite=Lax`;
}
