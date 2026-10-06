package com.xpn.xwiki.api;

/**
 * Standalone example of the same shape: a setter that changes state on the wrapped user object with no
 * permission check, because the wrapped object is the CALLER'S OWN preferences record (a user editing
 * their own display theme), not another account.
 */
class OwnPreferences {

    interface PreferenceStore {
        void setTheme(String theme);
    }

    private final PreferenceStore ownStore;

    OwnPreferences(PreferenceStore ownStore) {
        this.ownStore = ownStore;
    }

    public void setTheme(String theme) {
        this.ownStore.setTheme(theme);
    }
}
