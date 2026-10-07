// Standalone example of the same shape: decide whether to show a "connect
// your account" hint in the UI based on the configured server type and
// whether a host is set -- purely presentational; the actual login route is
// guarded separately.
export function shouldShowConnectHint(
  serverType: 'plex' | 'jellyfin' | 'none',
  hostConfigured: boolean
): boolean {
  return serverType !== 'none' && !hostConfigured;
}
