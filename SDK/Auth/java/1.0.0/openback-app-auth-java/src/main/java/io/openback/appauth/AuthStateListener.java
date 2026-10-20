package io.openback.appauth;

/** Told when the signed-in user or the active organization changes; both null when signed out. */
@FunctionalInterface
public interface AuthStateListener {
    void onAuthStateChanged(PoolUser user, ActiveOrg org);
}
