/*
 * FILE:      src/main/java/com/kwtsms/keycloak/HourlyCap.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4; rewritten onyx-fixes #1176
 * AUTHOR:    M Alhassoun
 * WHAT:      Hourly SMS caps (per user and per realm) kept in server-side storage: each SMS takes one numbered
 *            slot of the current clock hour, claimed with an atomic put-if-absent, so N slots mean at most N SMS.
 * WHY:       2026-11-09 23:37 +03 (onyx-fixes #1176, findings K1, K2, K3): the cap used to live in the user
 *            attribute kwtsms_sms_sent, which a read-only store (LDAP) cannot write and a user may be able to
 *            edit, and its read-modify-write let parallel logins pass together. The store behind this class is
 *            Keycloak's SingleUseObjectProvider (see SmsCodeAuthenticator), which users cannot reach, works for
 *            federated users, and is shared by every node of a cluster.
 * USAGE:     if (HourlyCap.tryTake(store, HourlyCap.userScope(realmId, userId), maxPerHour, now)) { send; }
 *            Any exception from the store must be treated as "no slot" by the caller (fail closed).
 * DEPENDS:   Java 17 only (the Keycloak adapter lives in SmsCodeAuthenticator, so this stays unit-testable).
 */
package com.kwtsms.keycloak;

public final class HourlyCap {

    /** Fixed window: one clock hour (epoch seconds / 3600). Keys carry the window number. */
    static final long WINDOW_SECONDS = 3600;
    /** Extra lifetime past the window end; harmless because a new window uses new keys. */
    static final long GRACE_SECONDS = 60;
    static final String PREFIX = "kwtsms-sms-cap:";

    /** The server-side store. Implementations must make {@link #claim} atomic across the cluster. */
    public interface Store {
        /** Put the key if it is absent; true when this call created it (the slot is ours). */
        boolean claim(String key, long lifespanSeconds);

        /** Read a hint value, or null. Hints only save lookups; correctness comes from claim. */
        String read(String key);

        /** Write a hint value (best effort, may be lost or late). */
        void write(String key, String value, long lifespanSeconds);
    }

    private HourlyCap() {
    }

    public static String userScope(String realmId, String userId) {
        return PREFIX + realmId + ":user:" + userId;
    }

    public static String realmScope(String realmId) {
        return PREFIX + realmId + ":realm";
    }

    static long window(long nowSeconds) {
        return Math.floorDiv(nowSeconds, WINDOW_SECONDS);
    }

    /** Seconds until the current window ends (1 to 3600): the longest a user can be held back by the cap. */
    public static long secondsLeft(long nowSeconds) {
        return WINDOW_SECONDS - Math.floorMod(nowSeconds, WINDOW_SECONDS);
    }

    /**
     * Take one of {@code max} slots of the current hour for {@code scope}. Returns false when all slots are
     * taken. Slots below the hint are always taken (a hint is only written after its slot was claimed and every
     * slot under it was found taken), so starting at the hint never skips a free slot.
     */
    public static boolean tryTake(Store store, String scope, int max, long nowSeconds) {
        if (max < 1) return false;
        String base = scope + ":" + window(nowSeconds) + ":";
        long lifespan = secondsLeft(nowSeconds) + GRACE_SECONDS;
        int start = 0;
        String hint = store.read(base + "next");
        if (hint != null) {
            try {
                start = Math.max(0, Math.min(max, Integer.parseInt(hint)));
            } catch (NumberFormatException ignored) {
                // a broken hint costs lookups, never a wrong answer
            }
        }
        for (int i = start; i < max; i++) {
            if (store.claim(base + i, lifespan)) {
                store.write(base + "next", Integer.toString(i + 1), lifespan);
                return true;
            }
        }
        return false;
    }
}
