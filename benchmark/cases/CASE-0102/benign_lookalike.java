import org.apache.camel.Exchange;
import org.apache.camel.support.DefaultHeaderFilterStrategy;
import org.apache.camel.support.http.HttpUtil;

public class ProducerOnlyHeaderFilterStrategy extends DefaultHeaderFilterStrategy {

    public ProducerOnlyHeaderFilterStrategy() {
        initialize();
    }

    protected void initialize() {
        HttpUtil.addCommonFilters(getOutFilter());

        setLowerCase(true);

        // same outbound-only configuration as a consumer-side strategy ...
        setOutFilterStartsWith(CAMEL_FILTER_STARTS_WITH);
    }

    /**
     * ... but this strategy belongs to a producer-only endpoint: no external
     * (inbound) header is ever allowed into the Camel message, so a client
     * cannot inject Camel* headers.
     */
    @Override
    public boolean applyFilterToExternalHeaders(String headerName, Object headerValue, Exchange exchange) {
        return true;
    }
}
