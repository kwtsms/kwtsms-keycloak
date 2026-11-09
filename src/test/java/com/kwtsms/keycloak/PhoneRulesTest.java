/*
 * FILE:      src/test/java/com/kwtsms/keycloak/PhoneRulesTest.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      Unit tests for phone resolution (default country code, kwtSMS validation), the country allowlist and masking.
 * WHY:       The security rules of the SMS code step must hold without a running Keycloak; no network.
 * USAGE:     ./gradlew test
 * DEPENDS:   JUnit 5.
 */
package com.kwtsms.keycloak;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PhoneRulesTest {

    @Test
    void localNumberGetsDefaultCountryCode() {
        assertEquals("96550000001", PhoneRules.resolve("5000 0001", "965"));
        assertEquals("96550000001", PhoneRules.resolve("50000001", "965"));
    }

    @Test
    void internationalFormsAreNormalized() {
        assertEquals("96550000001", PhoneRules.resolve("+965 5000 0001", "965"));
        assertEquals("96550000001", PhoneRules.resolve("0096550000001", "965"));
        assertEquals("96550000001", PhoneRules.resolve("96550000001", "965"));
    }

    @Test
    void arabicDigitsAreAccepted() {
        assertEquals("96550000001", PhoneRules.resolve("\u0669\u0666\u0665\u0665\u0660\u0660\u0660\u0660\u0660\u0660\u0661", "965"));
    }

    @Test
    void invalidOrMissingIsNull() {
        assertNull(PhoneRules.resolve(null, "965"));
        assertNull(PhoneRules.resolve("   ", "965"));
        assertNull(PhoneRules.resolve("user@example.com", "965"));
        assertNull(PhoneRules.resolve("abc", "965"));
        // Kuwait mobile numbers start with 4, 5, 6 or 9: 1xxxxxxx is not a mobile number
        assertNull(PhoneRules.resolve("10000001", "965"));
    }

    @Test
    void allowlist() {
        assertTrue(PhoneRules.allowed("96550000001", List.of("965")));
        assertFalse(PhoneRules.allowed("966500000001", List.of("965")));
        assertTrue(PhoneRules.allowed("966500000001", List.of("965", "966")));
        // 2026-11-09 23:37 +03 (onyx-fixes #1176, K4): an empty or missing list allows nothing.
        assertFalse(PhoneRules.allowed("447700900001", List.of()));
        assertFalse(PhoneRules.allowed("447700900001", null));
        assertFalse(PhoneRules.allowed(null, List.of("965")));
    }

    // 2026-11-09 23:37 +03 (onyx-fixes #1176, K8): first 3 and last 2 digits only.
    @Test
    void maskKeepsFirstThreeAndLastTwo() {
        assertEquals("965******01", PhoneRules.mask("96550000001"));
        assertEquals("966*******01", PhoneRules.mask("966500000001"));
        assertEquals("123***78", PhoneRules.mask("12345678"));
        assertEquals("*******", PhoneRules.mask("1234567"));
        assertEquals("(none)", PhoneRules.mask(null));
    }
}
