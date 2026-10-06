import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TicketPurger {

    private static final Logger logger = LoggerFactory.getLogger(TicketPurger.class);

    /**
     * Same loop-and-log-on-failure shape as a bulk delete, but each raw id is
     * parsed to a long BEFORE it is used or logged. Long.parseLong rejects
     * anything except an optional sign and digits (NumberFormatException), so
     * the value that reaches the logger can never contain CR/LF.
     */
    public boolean purgeTickets(String[] ticketIds) {
        boolean ok = true;
        if (ticketIds != null) {
            for (String raw : ticketIds) {
                long id = Long.parseLong(raw.trim());
                ok = purgeTicket(id);
                if (!ok) {
                    logger.warn("It cannot delete {} and breaking the loop", id);
                    break;
                }
            }
        }
        return ok;
    }

    private boolean purgeTicket(long id) {
        return id > 0;
    }
}
