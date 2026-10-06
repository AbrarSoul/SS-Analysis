import java.util.HashMap;
import java.util.Map;

import org.jivesoftware.openfire.event.UserEventDispatcher;
import org.jivesoftware.openfire.event.UserEventListener;
import org.jivesoftware.openfire.user.User;

public class DisplayNameCache {

    private final Map<String, String> displayNames = new HashMap<>();

    /**
     * Same constructor-registers-a-UserEventListener shape as the admin
     * manager fix, but the state it evicts on deletion is only a display-name
     * cache; nothing here grants or keeps a privilege for a username.
     */
    public DisplayNameCache() {
        UserEventDispatcher.addListener(new UserEventListener() {
            @Override
            public void userDeleting(final User user, final Map<String, Object> params) {
                displayNames.remove(user.getUsername());
            }

            @Override public void userCreated(final User user, final Map<String, Object> params) {}
            @Override public void userModified(final User user, final Map<String, Object> params) {}
        });
    }
}
