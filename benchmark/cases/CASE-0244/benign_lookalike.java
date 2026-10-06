package org.opencastproject.kernel.security;

/**
 * Standalone example of the same shape: a per-thread value that IS cleared in a
 * finally block after each unit of work, so a pooled thread never leaks it into
 * the next request.
 */
public class RequestLocal<T> {

    private final ThreadLocal<T> holder = new ThreadLocal<>();

    public T runWith(T value, java.util.function.Function<T, T> work) {
        holder.set(value);
        try {
            return work.apply(holder.get());
        } finally {
            holder.remove();
        }
    }
}
