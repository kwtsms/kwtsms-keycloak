/*
 * FILE:      src/test/java/com/kwtsms/keycloak/SmsCodeTest.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      Unit tests for code generation, hashing, constant-time compare, expiry, resend wait and TTL minutes.
 * WHY:       The security rules of the SMS code step must hold without a running Keycloak; no network.
 * USAGE:     ./gradlew test
 * DEPENDS:   JUnit 5.
 */
package com.kwtsms.keycloak;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SmsCodeTest {

    @Test
    void generatesOnlyDigitsOfTheRequestedLength() {
        for (int len = 4; len <= 10; len++) {
            String c = SmsCode.generate(len);
            assertEquals(len, c.length());
            assertTrue(c.matches("[0-9]+"), c);
        }
    }

    @Test
    void codesVary() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 200; i++) seen.add(SmsCode.generate(6));
        assertTrue(seen.size() > 190, "SecureRandom codes should rarely repeat");
    }

    @Test
    void rejectsNonPositiveLength() {
        assertThrows(IllegalArgumentException.class, () -> SmsCode.generate(0));
    }

    @Test
    void hashIsSha256Hex() {
        // SHA-256("123456"), known value
        assertEquals("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", SmsCode.hash("123456"));
    }

    @Test
    void matchesOnlyTheRightCode() {
        String h = SmsCode.hash("042917");
        assertTrue(SmsCode.matches("042917", h));
        assertTrue(SmsCode.matches(" 042917 ", h));
        assertFalse(SmsCode.matches("42917", h));
        assertFalse(SmsCode.matches("042918", h));
        assertFalse(SmsCode.matches("", h));
        assertFalse(SmsCode.matches(null, h));
        assertFalse(SmsCode.matches("042917", null));
        assertFalse(SmsCode.matches("042917", ""));
    }

    @Test
    void acceptsArabicAndPersianDigits() {
        String h = SmsCode.hash("042917");
        assertTrue(SmsCode.matches("\u0660\u0664\u0662\u0669\u0661\u0667", h));
        assertTrue(SmsCode.matches("\u06F0\u06F4\u06F2\u06F9\u06F1\u06F7", h));
    }

    @Test
    void expiry() {
        assertFalse(SmsCode.isExpired(1000, 1300));
        assertFalse(SmsCode.isExpired(1299, 1300));
        assertTrue(SmsCode.isExpired(1300, 1300));
        assertTrue(SmsCode.isExpired(1301, 1300));
    }

    @Test
    void resendWait() {
        assertEquals(180, SmsCode.resendWaitLeft(1000, 1000, 180));
        assertEquals(1, SmsCode.resendWaitLeft(1179, 1000, 180));
        assertEquals(0, SmsCode.resendWaitLeft(1180, 1000, 180));
        assertEquals(0, SmsCode.resendWaitLeft(5000, 1000, 180));
        // never sent (0) is far in the past: resend allowed
        assertEquals(0, SmsCode.resendWaitLeft(1_700_000_000L, 0, 180));
    }

    @Test
    void ttlMinutesRoundsUp() {
        assertEquals(5, SmsCode.ttlMinutes(300));
        assertEquals(6, SmsCode.ttlMinutes(301));
        assertEquals(1, SmsCode.ttlMinutes(60));
        assertEquals(1, SmsCode.ttlMinutes(1));
    }
}
