"""
Section 9 ground-truth test bundle: CASE-0175
(igniterealtime/Openfire, xmppserver/.../admin/AdminManager.java the private
constructor, CVE-2024-25420, CWE-273 improper check for dropped privileges).

Located target: `private AdminManager() {`.

Core vulnerable mechanism: AdminManager keeps the list of admin accounts by
JID and never reacts to a user being DELETED. If an administrator's account
is deleted and a new account is later created with the same username, the
JID is still in the admin list, so the new account is automatically an
administrator (privilege inherited by name). The upstream fix registers a
UserEventListener in the constructor whose `userDeleting` removes the
username from the admin list.

Sibling sites: none. removeAdminAccount already exists and is reused.

Every variant is the FULL real file. The constructor is private (called only
by the singleton holder), so the renamed variant renames the private static
initProvider and the holder class instead.

Verification: the Openfire runtime (SystemProperty, XMPPServer, JID, the
event dispatcher and providers) is not usable standalone, so the whole file is
compiled against small stand-ins with the same names and signatures the file
uses.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0175"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

CTOR = '''    private AdminManager() {
        // Load an admin provider.
        initProvider(ADMIN_PROVIDER.getValue());
    }
'''
assert original.count(CTOR) == 1


def swap(text, old, new, count=1):
    assert text.count(old) == count and new != old
    return text.replace(old, new)


IMPORTS = '''import java.util.ArrayList;
import java.util.List;

import org.jivesoftware.openfire.XMPPServer;
'''
LISTENER_IMPORTS = '''import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.event.UserEventDispatcher;
import org.jivesoftware.openfire.event.UserEventListener;
import org.jivesoftware.openfire.user.User;
'''
assert original.count(IMPORTS) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = original.replace("initProvider", "installProvider").replace("AdminManagerContainer", "AdminManagerHolder")
assert v1.count("installProvider") == 3 and "AdminManagerHolder" in v1 and "initProvider" not in v1
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CTOR, '''    private AdminManager() {
        loadConfiguredProvider();
    }

    private static void loadConfiguredProvider() {
        // Load an admin provider.
        initProvider(ADMIN_PROVIDER.getValue());
    }
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The listener cleans the name on BOTH deletion and creation (so a stale
# admin entry can never attach to a newly created account, even if it was
# left behind by a deletion that raised no event); upstream reacts to
# userDeleting only.
v3 = swap(original, IMPORTS, LISTENER_IMPORTS)
v3 = swap(v3, CTOR, '''    private AdminManager() {
        // Load an admin provider.
        initProvider(ADMIN_PROVIDER.getValue());

        UserEventDispatcher.addListener(new UserEventListener() {
            @Override
            public void userDeleting(final User user, final Map<String, Object> params) {
                removeAdminAccount(user.getUsername());
            }

            @Override
            public void userCreated(final User user, final Map<String, Object> params) {
                removeAdminAccount(user.getUsername());
            }

            @Override public void userModified(final User user, final Map<String, Object> params) {}
        });
    }
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.util.HashMap;
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
'''
assert "display-name" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0175.")
