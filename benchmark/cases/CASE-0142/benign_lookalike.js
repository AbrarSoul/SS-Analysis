/**
 * Same "read the Host header and compare it to a fixed list" shape as a
 * localhost check, but the result is only ever used to DENY (redirect a
 * request that arrived through a disabled tunnel host); it never grants
 * access to anything, so a spoofed Host header can only make things stricter
 * for the spoofer.
 */
export function arrivedViaBlockedTunnel(request, settings) {
  const host = (request.headers.get("host") || "").split(":")[0].toLowerCase();
  const blocked = [settings.tunnelHost, settings.tailscaleHost]
    .filter(Boolean)
    .map((h) => h.toLowerCase());
  return settings.tunnelDashboardAccess !== true && blocked.includes(host);
}
