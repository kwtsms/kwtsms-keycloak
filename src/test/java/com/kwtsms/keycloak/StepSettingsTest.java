/*
 * FILE:      src/test/java/com/kwtsms/keycloak/StepSettingsTest.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      Unit tests for step settings defaults, clamping of out-of-range numbers and the country code list.
 * WHY:       The security rules of the SMS code step must hold without a running Keycloak; no network.
 * USAGE:     ./gradlew test
 * DEPENDS:   JUnit 5.
 */
package com.kwtsms.keycloak;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class StepSettingsTest {

    @Test
    void defaultsWhenNoConfig() {
        StepSettings s = StepSettings.from(null);
        assertEquals("phone_number", s.phoneAttribute);
        assertEquals("965", s.defaultCountryCode);
        assertEquals(List.of("965"), s.allowedCountryCodes);
        assertEquals(6, s.codeLength);
        assertEquals(300, s.ttlSeconds);
        assertEquals(180, s.resendWaitSeconds);
        assertEquals(5, s.maxAttempts);
        assertEquals(5, s.maxPerHour);
        assertFalse(s.testMode);
        assertEquals("", s.senderId);
    }

    @Test
    void badNumbersNeverDisableALimit() {
        Map<String, String> c = new HashMap<>();
        c.put(StepSettings.MAX_ATTEMPTS, "0");
        c.put(StepSettings.MAX_PER_HOUR, "100000");
        c.put(StepSettings.CODE_LENGTH, "two");
        c.put(StepSettings.RESEND_WAIT, "-5");
        c.put(StepSettings.CODE_TTL, " ");
        StepSettings s = StepSettings.from(c);
        assertEquals(1, s.maxAttempts);
        assertEquals(50, s.maxPerHour);
        assertEquals(6, s.codeLength);
        assertEquals(30, s.resendWaitSeconds);
        assertEquals(300, s.ttlSeconds);
    }

    @Test
    void parsesListsAndFlags() {
        Map<String, String> c = new HashMap<>();
        c.put(StepSettings.ALLOWED_COUNTRY_CODES, " +965, 966  971 ");
        c.put(StepSettings.DEFAULT_COUNTRY_CODE, "+965");
        c.put(StepSettings.TEST_MODE, "true");
        c.put(StepSettings.SENDER_ID, " MY-SENDER ");
        StepSettings s = StepSettings.from(c);
        assertEquals(List.of("965", "966", "971"), s.allowedCountryCodes);
        assertEquals("965", s.defaultCountryCode);
        assertTrue(s.testMode);
        assertEquals("MY-SENDER", s.senderId);
    }

    // 2026-11-09 23:37 +03 (onyx-fixes #1176, K4): "*" no longer allows every country.
    @Test
    void starAllowsNoCountryButBlankKeepsTheDefault() {
        Map<String, String> c = new HashMap<>();
        c.put(StepSettings.ALLOWED_COUNTRY_CODES, "*");
        StepSettings s = StepSettings.from(c);
        assertTrue(s.allowedCountryCodes.isEmpty());
        assertFalse(PhoneRules.allowed("96550000001", s.allowedCountryCodes));
        c.put(StepSettings.ALLOWED_COUNTRY_CODES, "");
        assertEquals(List.of("965"), StepSettings.from(c).allowedCountryCodes);
    }

    // 2026-11-09 23:37 +03 (onyx-fixes #1176, K3): realm-wide ceiling, default 200, clamped 1 to 10000.
    @Test
    void realmCeilingDefaultAndClamp() {
        assertEquals(200, StepSettings.from(null).maxPerRealmHour);
        Map<String, String> c = new HashMap<>();
        c.put(StepSettings.MAX_PER_REALM_HOUR, "0");
        assertEquals(1, StepSettings.from(c).maxPerRealmHour);
        c.put(StepSettings.MAX_PER_REALM_HOUR, "99999999");
        assertEquals(10000, StepSettings.from(c).maxPerRealmHour);
        c.put(StepSettings.MAX_PER_REALM_HOUR, "lots");
        assertEquals(200, StepSettings.from(c).maxPerRealmHour);
    }
}
