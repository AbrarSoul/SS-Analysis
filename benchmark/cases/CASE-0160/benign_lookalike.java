package com.facebook.thrift.protocol;

import com.facebook.thrift.TException;

public class BoundedListSkipper {

  private static final int MAX_ELEMENTS = 1 << 20;

  /**
   * Same declared-size element loop as the protocol skipper, but the declared
   * size is bounded and every iteration actually consumes an element (an
   * unknown element type is rejected up front), so the loop cannot run
   * without reading.
   */
  public static void skipInts(TProtocol prot, TList list) throws TException {
    if (list.elemType != TType.I32 || list.size < 0 || list.size > MAX_ELEMENTS) {
      throw new TException("Unsupported list header");
    }
    for (int i = 0; i < list.size; i++) {
      prot.readI32();
    }
  }
}
