import java.util.Iterator;
import java.util.NoSuchElementException;

public class SequentialIds implements Iterator<Long>
{
    private final long end;
    private long current;

    public SequentialIds(long start, long count)
    {
        this.current = start;
        this.end = start + Math.max(0, count);
    }

    @Override
    public boolean hasNext()
    {
        return current < end;
    }

    /**
     * Same Iterator<Long> shape as the range-walking iterator, but over ONE
     * range and with the contract check: calling next() after exhaustion
     * throws NoSuchElementException instead of indexing past any array.
     */
    @Override
    public Long next()
    {
        if (current >= end)
        {
            throw new NoSuchElementException();
        }
        return current++;
    }
}
