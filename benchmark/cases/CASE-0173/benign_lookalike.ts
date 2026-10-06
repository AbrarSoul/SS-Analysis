const DEFAULT_PAGE = 'index.html'

/**
 * Same `manifest[name] || <fallback>` shape as the KV asset lookup, but the
 * fallback is a developer-written constant, never the caller's input, so an
 * unknown name can only ever resolve to the public default page.
 */
export const resolvePublicKey = (manifest: Record<string, string>, name: string): string => {
  return manifest[name] || DEFAULT_PAGE
}
