// Standalone example of the same shape: skip an EXPENSIVE thumbnail
// regeneration step if one was already generated for this exact image
// hash (a cache-hit optimization), never a security boundary -- serving
// the cached thumbnail again is harmless either way.
async function regenerateThumbnailIfNeeded (imageHash, thumbnailStore) {
  const cached = await thumbnailStore.has(imageHash).catch(() => false);
  if (cached) return thumbnailStore.get(imageHash);
  return thumbnailStore.generate(imageHash);
}

module.exports = { regenerateThumbnailIfNeeded };
