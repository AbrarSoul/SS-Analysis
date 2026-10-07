public class AttemptCounter {

    private final int maxAttempts;
    private int attempts = 0;

    public AttemptCounter(int maxAttempts) {
        this.maxAttempts = maxAttempts;
    }

    /**
     * Same "increment, then compare with the limit" order, but this counter
     * is DEFINED as the number of ATTEMPTS (accepted or rejected), and that
     * is exactly what attemptsSoFar() reports and what the audit log wants,
     * so counting the rejected attempt is the intended behaviour, not a
     * miscount.
     */
    public void recordAttempt() {
        attempts++;
        if (maxAttempts > -1 && attempts > maxAttempts) {
            throw new IllegalStateException("Too many attempts: " + maxAttempts);
        }
    }

    public int attemptsSoFar() {
        return attempts;
    }
}
