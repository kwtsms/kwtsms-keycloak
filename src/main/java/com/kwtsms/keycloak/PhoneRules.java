/*
 * FILE:      src/main/java/com/kwtsms/keycloak/PhoneRules.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      Turns the phone attribute of a user into an international number kwtSMS accepts, checks it against
 *            the allowed country codes, and masks it for logs.
 * WHY:       Same normalization and country rules as every kwtSMS library (kwtsms-java PhoneUtils, bundled and
 *            relocated), plus a country allowlist against toll fraud, and no full number in any log.
 * USAGE:     String n = PhoneRules.resolve(raw, "965"); if (n != null && PhoneRules.allowed(n, list)) ...
 *            PhoneRules.mask(n)  // 96550000001 becomes 96550****01
 * DEPENDS:   com.kwtsms.PhoneUtils (kwtsms-java 0.5.0, relocated to com.kwtsms.keycloak.lib in the jar).
 */
package com.kwtsms.keycloak;

import com.kwtsms.PhoneUtils;

import java.util.List;

public final class PhoneRules {

    /** Numbers of this many digits or fewer, written without + or 00, are local and get the default country code. */
    static final int MAX_LOCAL_DIGITS = 8;

    private PhoneRules() {
    }

    /**
     * Normalize and validate a stored phone number. Returns the international digits (no +), or null when the
     * value is empty or fails the kwtSMS validation rules.
     */
    public static String resolve(String raw, String defaultCountryCode) {
        if (raw == null || raw.trim().isEmpty()) return null;
        String trimmed = raw.trim();
        boolean international = trimmed.startsWith("+") || trimmed.startsWith("00");
        String n = PhoneUtils.normalizePhone(trimmed);
        if (n.isEmpty()) return null;
        if (!international && n.length() <= MAX_LOCAL_DIGITS && defaultCountryCode != null
                && !defaultCountryCode.isEmpty()) {
            n = defaultCountryCode + n;
        }
        PhoneUtils.ValidationResult vr = PhoneUtils.validatePhoneInput(n);
        return vr.isValid() ? vr.getNormalized() : null;
    }

    /** True when the number starts with one of the allowed country codes; an empty list allows every code. */
    public static boolean allowed(String normalized, List<String> allowedCodes) {
        if (normalized == null) return false;
        if (allowedCodes == null || allowedCodes.isEmpty()) return true;
        for (String cc : allowedCodes) {
            if (!cc.isEmpty() && normalized.startsWith(cc)) return true;
        }
        return false;
    }

    /** Keep the first 5 and last 2 digits, star the rest; numbers shorter than 8 digits are fully starred. */
    public static String mask(String number) {
        if (number == null || number.isEmpty()) return "(none)";
        int len = number.length();
        if (len < 8) return "*".repeat(len);
        return number.substring(0, 5) + "*".repeat(len - 7) + number.substring(len - 2);
    }
}
