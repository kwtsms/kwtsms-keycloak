/*
 * FILE:      src/main/java/com/kwtsms/keycloak/SmsCode.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      SMS code primitives: SecureRandom digit codes, SHA-256 hashing, constant-time compare, expiry and
 *            resend-wait arithmetic.
 * WHY:       Only the hash of a code is kept in the authentication session; comparing in constant time and
 *            keeping the time rules in pure functions makes them unit-testable without Keycloak.
 * USAGE:     String code = SmsCode.generate(6); String h = SmsCode.hash(key, code); SmsCode.matches(input, h, key, 6);
 *            (2026-11-09 23:37 +03, onyx-fixes #1176: keyed HMAC and a length limit, findings K5 and K7)
 * DEPENDS:   Java 17 only.
 */
package com.kwtsms.keycloak;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class SmsCode {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private SmsCode() {
    }

    /** A code of {@code length} decimal digits, each drawn uniformly from SecureRandom; leading zeros allowed. */
    public static String generate(int length) {
        if (length < 1) throw new IllegalArgumentException("length must be positive");
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('0' + RANDOM.nextInt(10)));
        }
        return sb.toString();
    }

    /**
     * Lower-case hex HMAC-SHA256 of the code (UTF-8) under {@code key}.
     * 2026-11-09 23:37 +03 (onyx-fixes #1176, K5): was a plain SHA-256, which anyone reading the session store
     * could reverse in microseconds (10^6 codes). The key is a server secret that is not in the session store
     * (KwtsmsSender.codeKey, derived from the API login in the server config), so a dump alone is not enough.
     */
    public static String hash(byte[] key, String code) {
        if (key == null || key.length == 0) throw new IllegalArgumentException("key must not be empty");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] d = mac.doFinal(code.getBytes(StandardCharsets.UTF_8));
            char[] out = new char[d.length * 2];
            for (int i = 0; i < d.length; i++) {
                out[i * 2] = HEX[(d[i] >> 4) & 0xF];
                out[i * 2 + 1] = HEX[d[i] & 0xF];
            }
            return new String(out);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HmacSHA256 not available", e);
        }
    }

    /**
     * True when the typed code hashes to the stored hash. The input is trimmed and Arabic-Indic or Persian
     * digits are read as Latin digits (phones with an Arabic keyboard). Hashes are compared in constant time.
     * 2026-11-09 23:37 +03 (onyx-fixes #1176, K7): input longer than {@code maxLength} (after trim) is rejected
     * before any work, so an oversized form value is never processed.
     */
    public static boolean matches(String input, String storedHash, byte[] key, int maxLength) {
        if (input == null || storedHash == null || storedHash.isEmpty() || key == null || key.length == 0) return false;
        String trimmed = input.trim();
        if (trimmed.isEmpty() || trimmed.length() > maxLength) return false;
        String typed = latinDigits(trimmed);
        return MessageDigest.isEqual(hash(key, typed).getBytes(StandardCharsets.US_ASCII),
                storedHash.getBytes(StandardCharsets.US_ASCII));
    }

    static String latinDigits(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch >= '\u0660' && ch <= '\u0669') sb.append((char) ('0' + (ch - '\u0660')));
            else if (ch >= '\u06F0' && ch <= '\u06F9') sb.append((char) ('0' + (ch - '\u06F0')));
            else sb.append(ch);
        }
        return sb.toString();
    }

    /** True when now is at or past the expiry time (both epoch seconds). */
    public static boolean isExpired(long nowSeconds, long expiresAtSeconds) {
        return nowSeconds >= expiresAtSeconds;
    }

    /** Seconds the user still has to wait before a resend; 0 means a resend is allowed now. */
    public static long resendWaitLeft(long nowSeconds, long lastSentSeconds, int waitSeconds) {
        long left = lastSentSeconds + waitSeconds - nowSeconds;
        return Math.max(0, left);
    }

    /** Code lifetime shown to the user, rounded up to whole minutes (300 s is 5, 330 s is 6). */
    public static int ttlMinutes(int ttlSeconds) {
        return (ttlSeconds + 59) / 60;
    }
}
