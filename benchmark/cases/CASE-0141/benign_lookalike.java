import java.time.ZonedDateTime;
import java.util.function.Supplier;

public class RefreshingValue<T>
{
	private record Entry<T>(ZonedDateTime refreshAt, T value)
	{
	}

	private Entry<T> entry;

	/**
	 * Same isBefore(now) comparison on a cache timeout as an access-token
	 * cache, but used the correct way round: isBefore means the refresh
	 * deadline has passed, so the entry is REPLACED, and only a deadline still
	 * in the future is served from the cache.
	 */
	public T get(Supplier<T> loader, ZonedDateTime newRefreshAt)
	{
		if (entry == null || entry.refreshAt.isBefore(ZonedDateTime.now()))
		{
			entry = new Entry<T>(newRefreshAt, loader.get());
		}
		return entry.value;
	}
}
