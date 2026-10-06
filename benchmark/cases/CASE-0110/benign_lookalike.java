public final class FixedChunk
{
  private static final int CHUNK_SIZE = 4096;

  byte[] _buf;

  /**
   * Same `new byte[length]` allocation followed by System.arraycopy, but the
   * length is NOT taken from the caller: it is derived from the real source
   * array and capped at CHUNK_SIZE, so the allocation is bounded no matter
   * what offset is passed.
   */
  public FixedChunk(byte[] source, int offset)
  {
    if (offset < 0 || offset > source.length)
    {
      throw new IndexOutOfBoundsException("offset " + offset + " outside 0.." + source.length);
    }
    int length = Math.min(CHUNK_SIZE, source.length - offset);
    _buf = new byte[length];
    System.arraycopy(source, offset, _buf, 0, length);
  }
}
