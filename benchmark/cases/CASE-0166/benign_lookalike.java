public final class GrowthPlanner {

    private static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;

    /**
     * Same "current length + requested amount" computation as ensureCapacity,
     * but done in long arithmetic and checked against the maximum array size
     * before narrowing back to int, so it can never overflow.
     */
    public static int newCapacity(final int currentLength, final int requested) {
        final long wanted = (long) currentLength + requested;
        if (wanted < 0 || wanted > MAX_ARRAY_SIZE) {
            throw new IllegalArgumentException("capacity out of range: " + wanted);
        }
        return (int) wanted;
    }
}
