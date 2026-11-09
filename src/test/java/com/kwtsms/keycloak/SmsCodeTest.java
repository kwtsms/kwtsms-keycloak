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

    // 2026-11-09 23:37 +03 (onyx-fixes #1176, K5, K7): keyed HMAC instead of plain SHA-256, and a length limit.
    private static final byte[] KEY = "test-key".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @Test
    void hashIsHmacSha256Hex() {
        // HMAC-SHA256(key "test-key", "123456"), known value (python3 hmac)
        assertEquals("3208c5c65614f51aab0ffa05bfd314e635f567d7873e42e1e660787eec2b7f2d", SmsCode.hash(KEY, "123456"));
        assertThrows(IllegalArgumentException.class, () -> SmsCode.hash(new byte[0], "123456"));
    }

    @Test
    void anotherKeyGivesAnotherHash() {
        assertNotEquals(SmsCode.hash(KEY, "123456"), SmsCode.hash("other".getBytes(), "123456"));
        assertFalse(SmsCode.matches("123456", SmsCode.hash(KEY, "123456"), "other".getBytes(), 6));
        assertFalse(SmsCode.matches("123456", SmsCode.hash(KEY, "123456"), null, 6));
    }

    @Test
    void matchesOnlyTheRightCode() {
        String h = SmsCode.hash(KEY, "042917");
        assertTrue(SmsCode.matches("042917", h, KEY, 6));
        assertTrue(SmsCode.matches(" 042917 ", h, KEY, 6));
        assertFalse(SmsCode.matches("42917", h, KEY, 6));
        assertFalse(SmsCode.matches("042918", h, KEY, 6));
        assertFalse(SmsCode.matches("", h, KEY, 6));
        assertFalse(SmsCode.matches(null, h, KEY, 6));
        assertFalse(SmsCode.matches("042917", null, KEY, 6));
        assertFalse(SmsCode.matches("042917", "", KEY, 6));
    }

    @Test
    void inputLongerThanTheCodeIsRejected() {
        String h = SmsCode.hash(KEY, "042917");
        assertFalse(SmsCode.matches("0429170", h, KEY, 6));
        assertFalse(SmsCode.matches("9".repeat(100_000), h, KEY, 6));
        assertTrue(SmsCode.matches("   042917   ", h, KEY, 6));
    }

    @Test
    void acceptsArabicAndPersianDigits() {
        String h = SmsCode.hash(KEY, "042917");
        assertTrue(SmsCode.matches("\u0660\u0664\u0662\u0669\u0661\u0667", h, KEY, 6));
        assertTrue(SmsCode.matches("\u06F0\u06F4\u06F2\u06F9\u06F1\u06F7", h, KEY, 6));
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

    // 2026-11-09 23:53 +03 (onyx-fixes #1176, N2): a page reload never sends another SMS while a code is live or inside the resend wait.
    @Test
    void reloadKeepsTheCurrentCode() {
        long sent = 1_000_000L;
        int wait = 180;
        long expires = sent + 300;
        assertTrue(SmsCode.keepCurrentCode(true, sent + 1, expires, sent, wait));
        assertTrue(SmsCode.keepCurrentCode(true, sent + 299, expires, sent, wait));
        // expired but still inside the resend wait (wait longer than the lifetime): no new SMS
        assertTrue(SmsCode.keepCurrentCode(true, sent + 400, sent + 300, sent, 600));
        // expired and the wait is over: a new code may be sent
        assertFalse(SmsCode.keepCurrentCode(true, sent + 300, expires, sent, wait));
        // no code yet (first visit, or the last send failed): send
        assertFalse(SmsCode.keepCurrentCode(false, sent + 1, expires, sent, wait));
    }

    // 2026-11-10 00:07 +03 (onyx-fixes #1176, N2 remainder): a failed send keeps the resend wait, a reload inside it does not try again.
    @Test
    void failedSendKeepsTheResendWait() {
        long sent = 1_000_000L;
        int wait = 180;
        assertTrue(SmsCode.holdAfterFailedSend(false, sent, sent, wait));
        assertTrue(SmsCode.holdAfterFailedSend(false, sent + 179, sent, wait));
        assertFalse(SmsCode.holdAfterFailedSend(false, sent + 180, sent, wait));
        // first visit: no attempt recorded yet
        assertFalse(SmsCode.holdAfterFailedSend(false, sent, 0, wait));
        // a code is held: keepCurrentCode decides, not this rule
        assertFalse(SmsCode.holdAfterFailedSend(true, sent + 1, sent, wait));
    }
}
