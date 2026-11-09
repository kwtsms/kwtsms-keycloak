/*
 * FILE:      src/main/java/com/kwtsms/keycloak/HourlyCap.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      Per-user hourly SMS cap: reads the send timestamps stored in a user attribute, drops the ones older
 *            than one hour, and says whether one more SMS is allowed.
 * WHY:       Stops one account from being used to send unlimited SMS (toll fraud, cost); the attribute survives
 *            new login attempts, unlike authentication session notes.
 * USAGE:     List<Long> recent = HourlyCap.trim(user.getAttributeStream(ATTR).toList(), now);
 *            if (HourlyCap.allowed(recent, max)) { send; recent.add(now); store HourlyCap.toStrings(recent); }
 * DEPENDS:   Java 17 only.
 */
package com.kwtsms.keycloak;

import java.util.ArrayList;
import java.util.List;

public final class HourlyCap {

    /** User attribute that holds the epoch seconds of each SMS sent to this user in the last hour. */
    public static final String ATTRIBUTE = "kwtsms_sms_sent";
    static final long WINDOW_SECONDS = 3600;

    private HourlyCap() {
    }

    /** Parse stored values and keep only timestamps inside the last hour (and not in the future), oldest first. */
    public static List<Long> trim(List<String> stored, long nowSeconds) {
        List<Long> out = new ArrayList<>();
        if (stored == null) return out;
        for (String s : stored) {
            if (s == null) continue;
            try {
                long t = Long.parseLong(s.trim());
                if (t > nowSeconds - WINDOW_SECONDS && t <= nowSeconds) out.add(t);
            } catch (NumberFormatException ignored) {
                // a hand-edited or corrupt value is dropped, never trusted
            }
        }
        out.sort(Long::compare);
        return out;
    }

    /** True when fewer than {@code maxPerHour} SMS were sent in the trimmed window. */
    public static boolean allowed(List<Long> recent, int maxPerHour) {
        return recent.size() < maxPerHour;
    }

    public static List<String> toStrings(List<Long> recent) {
        List<String> out = new ArrayList<>(recent.size());
        for (Long t : recent) out.add(Long.toString(t));
        return out;
    }
}
