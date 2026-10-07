/**
 * Same "JSON string -> resource bin" step as an integrity resource, but the
 * bytes are copied into an exact-size ArrayBuffer, so nothing from the shared
 * Buffer pool ends up in the resource.
 */
export function jsonResourceBin(value: unknown): ArrayBuffer {
  const bytes = Buffer.from(JSON.stringify(value), 'utf-8');
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
