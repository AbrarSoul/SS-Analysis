// __STATIC_CONTENT is KVNamespace
declare const __STATIC_CONTENT: unknown
declare const __STATIC_CONTENT_MANIFEST: string

export type KVAssetOptions = {
  manifest?: object | string
  // namespace is KVNamespace
  namespace?: unknown
}

export const getContentFromKVAsset = async (
  assetPath: string,
  opts?: KVAssetOptions
): Promise<ReadableStream | null> => {
  let manifestMap: Record<string, string>

  if (opts && opts.manifest) {
    if (typeof opts.manifest === 'string') {
      manifestMap = JSON.parse(opts.manifest)
    } else {
      manifestMap = opts.manifest as Record<string, string>
    }
  } else {
    if (typeof __STATIC_CONTENT_MANIFEST === 'string') {
      manifestMap = JSON.parse(__STATIC_CONTENT_MANIFEST)
    } else {
      manifestMap = __STATIC_CONTENT_MANIFEST
    }
  }

  // ASSET_NAMESPACE is KVNamespace
  let kvNamespace: unknown
  if (opts && opts.namespace) {
    kvNamespace = opts.namespace
  } else {
    kvNamespace = __STATIC_CONTENT
  }

  const storageKey = manifestMap[assetPath] || assetPath
  if (!storageKey) {
    return null
  }

  // @ts-expect-error ASSET_NAMESPACE is not typed
  const body = await kvNamespace.get(storageKey, { type: 'stream' })
  if (!body) {
    return null
  }
  return body as unknown as ReadableStream
}
