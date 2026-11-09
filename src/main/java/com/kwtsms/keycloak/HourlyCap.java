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
 *            2026-11-09 23:53 +03 (onyx-fixes #1176, N1, N2): a third scope per client IP, so one address cannot
 *            drain the realm ceiling; and slots taken for an SMS that was never sent can be released.
 *            2026-11-10 00:07 +03 (onyx-fixes #1176, C3): the IP key is normalized (IPv6 by its /64 prefix).
 * USAGE:     if (HourlyCap.tryTake(store, HourlyCap.userScope(realmId, userId), maxPerHour, now)) { send; }
 *            int refused = HourlyCap.takeAll(store, scopes, max, now, taken);   // -1 = every slot taken
 *            HourlyCap.releaseAll(store, taken, now);                          // the send failed
 *            Any exception from the store must be treated as "no slot" by the caller (fail closed).
 * DEPENDS:   Java 17 only (the Keycloak adapter lives in SmsCodeAuthenticator, so this stays unit-testable).
 */
package com.kwtsms.keycloak;

import java.util.ArrayList;
import java.util.List;

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

        /** Remove a claimed slot. 2026-11-09 23:53 +03 (onyx-fixes #1176, N2): give back a slot not used. */
        void release(String key);
    }

    private HourlyCap() {
    }

    public static String userScope(String realmId, String userId) {
        return PREFIX + realmId + ":user:" + userId;
    }

    public static String realmScope(String realmId) {
        return PREFIX + realmId + ":realm";
    }

    /**
     * 2026-11-09 23:53 +03 (onyx-fixes #1176, N1): per client IP inside one realm.
     * 2026-11-10 00:07 +03 (onyx-fixes #1176, C3): keyed by {@link #ipKey}, so an IPv6 client shares one bucket
     * with its whole /64.
     */
    public static String ipScope(String realmId, String ip) {
        return PREFIX + realmId + ":ip:" + ipKey(ip);
    }

    private static final java.util.regex.Pattern IPV4 =
            java.util.regex.Pattern.compile("(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}");
    private static final java.util.regex.Pattern IPV6_CHARS = java.util.regex.Pattern.compile("[0-9A-Fa-f:.]+");

    /**
     * The bucket key of a client address: IPv4 as is; IPv6 as its /64 prefix (one end site usually holds a whole
     * /64, so an attacker could rotate addresses inside it); IPv4-mapped IPv6 (::ffff:a.b.c.d) as the IPv4
     * address; missing or unparseable as "unknown". Only literals are parsed, never a DNS lookup: anything that
     * is not dotted-quad IPv4 or hex/colon IPv6 text is "unknown" before InetAddress sees it.
     * 2026-11-10 00:07 +03 (onyx-fixes #1176, C3).
     */
    static String ipKey(String ip) {
        if (ip == null) return "unknown";
        String t = ip.trim();
        if (IPV4.matcher(t).matches()) return t;
        if (t.startsWith("[") && t.endsWith("]")) t = t.substring(1, t.length() - 1);
        int zone = t.indexOf('%');
        if (zone >= 0) t = t.substring(0, zone);
        if (t.indexOf(':') < 0 || !IPV6_CHARS.matcher(t).matches()) return "unknown";
        java.net.InetAddress a;
        try {
            a = java.net.InetAddress.getByName(t); // a literal with ':' is parsed, never looked up
        } catch (java.net.UnknownHostException | RuntimeException e) {
            return "unknown";
        }
        byte[] b = a.getAddress();
        if (b.length == 4) return a.getHostAddress(); // Java returns ::ffff:a.b.c.d as an Inet4Address
        if (b.length != 16) return "unknown";
        StringBuilder k = new StringBuilder();
        for (int i = 0; i < 8; i += 2) {
            k.append(Integer.toHexString(((b[i] & 0xff) << 8) | (b[i + 1] & 0xff))).append(':');
        }
        return k.append(":/64").toString();
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
        return take(store, scope, max, nowSeconds) != null;
    }

    /**
     * Like {@link #tryTake}, but returns the key of the slot taken (for {@link #release}), or null when all are
     * taken. 2026-11-09 23:53 +03 (onyx-fixes #1176, N2).
     */
    public static String take(Store store, String scope, int max, long nowSeconds) {
        if (max < 1) return null;
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
                return base + i;
            }
        }
        return null;
    }

    /**
     * Give back a slot from {@link #take}: remove it, then lower the hint to it so the next take finds it. A racing
     * take may raise the hint again past the freed slot; that only skips a free slot (fewer SMS), never more.
     * 2026-11-09 23:53 +03 (onyx-fixes #1176, N2).
     */
    public static void release(Store store, String slotKey, long nowSeconds) {
        store.release(slotKey);
        int cut = slotKey.lastIndexOf(':');
        int slot;
        try {
            slot = Integer.parseInt(slotKey.substring(cut + 1));
        } catch (NumberFormatException e) {
            return;
        }
        String hintKey = slotKey.substring(0, cut + 1) + "next";
        String hint = store.read(hintKey);
        int current;
        try {
            current = hint == null ? Integer.MAX_VALUE : Integer.parseInt(hint);
        } catch (NumberFormatException e) {
            current = Integer.MAX_VALUE;
        }
        if (current > slot) store.write(hintKey, Integer.toString(slot), secondsLeft(nowSeconds) + GRACE_SECONDS);
    }

    /**
     * Take one slot in each scope, in order. Returns -1 when every slot was taken (their keys are added to
     * {@code taken}), or the index of the first scope that is full; then the slots this call took are released
     * again, so a refused SMS uses no slot anywhere. 2026-11-09 23:53 +03 (onyx-fixes #1176, N1, N2).
     */
    public static int takeAll(Store store, String[] scopes, int[] max, long nowSeconds, List<String> taken) {
        List<String> mine = new ArrayList<>();
        try {
            for (int i = 0; i < scopes.length; i++) {
                String key = take(store, scopes[i], max[i], nowSeconds);
                if (key == null) {
                    releaseAll(store, mine, nowSeconds);
                    return i;
                }
                mine.add(key);
            }
        } catch (RuntimeException e) {
            releaseAll(store, mine, nowSeconds);
            throw e;
        }
        taken.addAll(mine);
        return -1;
    }

    /**
     * Release every slot in {@code taken} and clear the list. Best effort: a store error leaves that slot taken
     * (it expires with its hour), never throws. Returns how many could not be released.
     * 2026-11-09 23:53 +03 (onyx-fixes #1176, N2).
     */
    public static int releaseAll(Store store, List<String> taken, long nowSeconds) {
        int failed = 0;
        for (String key : taken) {
            try {
                release(store, key, nowSeconds);
            } catch (RuntimeException e) {
                failed++;
            }
        }
        taken.clear();
        return failed;
    }
}
