/*
 * FILE:      src/main/java/com/kwtsms/keycloak/StepSettings.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      The non-secret settings of one "kwtSMS SMS code" step: config keys, defaults, and parsing from the
 *            admin console config map, with every number clamped to a safe range.
 * WHY:       One place for keys and defaults, used by the factory (admin form) and the authenticator (runtime);
 *            a bad value typed in the admin console must never disable a limit.
 * USAGE:     StepSettings s = StepSettings.from(configMap);  // configMap may be null (no config saved yet)
 * DEPENDS:   Java 17 only.
 */
package com.kwtsms.keycloak;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public final class StepSettings {

    public static final String PHONE_ATTRIBUTE = "kwtsms.phone.attribute";
    public static final String DEFAULT_COUNTRY_CODE = "kwtsms.default.country.code";
    public static final String ALLOWED_COUNTRY_CODES = "kwtsms.allowed.country.codes";
    public static final String CODE_LENGTH = "kwtsms.code.length";
    public static final String CODE_TTL = "kwtsms.code.ttl.seconds";
    public static final String RESEND_WAIT = "kwtsms.resend.wait.seconds";
    public static final String MAX_ATTEMPTS = "kwtsms.max.attempts";
    public static final String MAX_PER_HOUR = "kwtsms.max.sms.per.hour";
    // 2026-11-09 23:37 +03 (onyx-fixes #1176, K3): realm-wide ceiling of SMS codes per clock hour, all users together.
    public static final String MAX_PER_REALM_HOUR = "kwtsms.max.sms.per.realm.hour";
    public static final String TEST_MODE = "kwtsms.test.mode";
    public static final String TEMPLATE_EN = "kwtsms.template.en";
    public static final String TEMPLATE_AR = "kwtsms.template.ar";
    public static final String SENDER_ID = "kwtsms.sender.id";

    public static final String DEF_PHONE_ATTRIBUTE = "phone_number";
    public static final String DEF_COUNTRY_CODE = "965";
    public static final String DEF_ALLOWED = "965";
    public static final int DEF_CODE_LENGTH = 6;
    public static final int DEF_TTL = 300;
    public static final int DEF_RESEND_WAIT = 180;
    public static final int DEF_MAX_ATTEMPTS = 5;
    public static final int DEF_MAX_PER_HOUR = 5;
    public static final int DEF_MAX_PER_REALM_HOUR = 200; // 2026-11-09 23:37 +03 (onyx-fixes #1176, K3)
    public static final String DEF_TEMPLATE_EN = "Your {realm} SMS code is {code}. It expires in {ttl_minutes} minutes.";
    public static final String DEF_TEMPLATE_AR = "رمز التحقق لدخول {realm}: {code}، صالح لمدة {ttl_minutes} دقائق.";

    public final String phoneAttribute;
    public final String defaultCountryCode;
    public final List<String> allowedCountryCodes;
    public final int codeLength;
    public final int ttlSeconds;
    public final int resendWaitSeconds;
    public final int maxAttempts;
    public final int maxPerHour;
    public final int maxPerRealmHour; // 2026-11-09 23:37 +03 (onyx-fixes #1176, K3)
    public final boolean testMode;
    public final String templateEn;
    public final String templateAr;
    public final String senderId;

    private StepSettings(Map<String, String> c) {
        phoneAttribute = text(c, PHONE_ATTRIBUTE, DEF_PHONE_ATTRIBUTE);
        defaultCountryCode = digits(text(c, DEFAULT_COUNTRY_CODE, DEF_COUNTRY_CODE));
        allowedCountryCodes = list(text(c, ALLOWED_COUNTRY_CODES, DEF_ALLOWED));
        codeLength = number(c, CODE_LENGTH, DEF_CODE_LENGTH, 4, 10);
        ttlSeconds = number(c, CODE_TTL, DEF_TTL, 60, 3600);
        resendWaitSeconds = number(c, RESEND_WAIT, DEF_RESEND_WAIT, 30, 3600);
        maxAttempts = number(c, MAX_ATTEMPTS, DEF_MAX_ATTEMPTS, 1, 10);
        maxPerHour = number(c, MAX_PER_HOUR, DEF_MAX_PER_HOUR, 1, 50);
        // 2026-11-09 23:37 +03 (onyx-fixes #1176, K3): 1 to 10000; a typo can lower the ceiling but never remove it.
        maxPerRealmHour = number(c, MAX_PER_REALM_HOUR, DEF_MAX_PER_REALM_HOUR, 1, 10000);
        testMode = "true".equalsIgnoreCase(text(c, TEST_MODE, "false"));
        templateEn = text(c, TEMPLATE_EN, DEF_TEMPLATE_EN);
        templateAr = text(c, TEMPLATE_AR, DEF_TEMPLATE_AR);
        senderId = c == null || c.get(SENDER_ID) == null ? "" : c.get(SENDER_ID).trim();
    }

    /** Build the settings from a step config map; null or blank values fall back to the defaults. */
    public static StepSettings from(Map<String, String> config) {
        return new StepSettings(config);
    }

    private static String text(Map<String, String> c, String key, String def) {
        if (c == null) return def;
        String v = c.get(key);
        return v == null || v.trim().isEmpty() ? def : v.trim();
    }

    /** A number outside [min, max] or not a number becomes the nearest bound or the default. */
    static int number(Map<String, String> c, String key, int def, int min, int max) {
        String v = text(c, key, null);
        int n;
        try {
            n = v == null ? def : Integer.parseInt(v);
        } catch (NumberFormatException e) {
            n = def;
        }
        return Math.max(min, Math.min(max, n));
    }

    private static String digits(String s) {
        return s == null ? "" : s.replaceAll("[^0-9]", "");
    }

    /**
     * "965, 966" to [965, 966]. 2026-11-09 23:37 +03 (onyx-fixes #1176, K4): "*" no longer means every country; it and any
     * value without digits give an empty list, and an empty list allows no country (the step fails closed).
     */
    static List<String> list(String s) {
        List<String> out = new ArrayList<>();
        if (s != null) {
            for (String p : s.split("[,\\s]+")) {
                String d = digits(p);
                if (!d.isEmpty()) out.add(d);
            }
        }
        return Collections.unmodifiableList(out);
    }
}
