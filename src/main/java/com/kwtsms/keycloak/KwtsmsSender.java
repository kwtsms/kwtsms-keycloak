/*
 * FILE:      src/main/java/com/kwtsms/keycloak/KwtsmsSender.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      Sends one SMS through the kwtSMS API with the bundled kwtsms-java client and returns a small result
 *            (ok, error code, message id) without the credentials.
 * WHY:       Keeps the HTTP call, message cleaning and error mapping in the shared client library; the
 *            authenticator only sees ok or an error code.
 * USAGE:     KwtsmsSender.Result r = new KwtsmsSender(user, pass).send("96550000001", text, "MY-SENDER", false);
 * DEPENDS:   com.kwtsms.KwtSMS and SendResult (kwtsms-java 0.5.0, relocated to com.kwtsms.keycloak.lib in the jar).
 */
package com.kwtsms.keycloak;

import com.kwtsms.KwtSMS;
import com.kwtsms.SendResult;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class KwtsmsSender {

    /** Sent before the library token in the User-Agent so kwtSMS can count requests per integration. */
    static final String APP_TOKEN = "kwtsms-keycloak/" + version();

    private final String username;
    private final String password;

    public KwtsmsSender(String username, String password) {
        this.username = username == null ? "" : username;
        this.password = password == null ? "" : password;
    }

    public boolean hasCredentials() {
        return !username.isEmpty() && !password.isEmpty();
    }

    /**
     * 2026-11-09 23:37 +03 (onyx-fixes #1176, K5): HMAC key for SMS code hashes, SHA-256 of a fixed label plus the
     * API login. It comes from the server config, so it is the same on every cluster node and is never in the
     * session store or the database. Never logged. Changing the API password only invalidates codes in flight.
     */
    byte[] codeKey() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update("kwtsms-keycloak code key v1".getBytes(StandardCharsets.UTF_8));
            md.update((byte) 0);
            md.update(username.getBytes(StandardCharsets.UTF_8));
            md.update((byte) 0);
            md.update(password.getBytes(StandardCharsets.UTF_8));
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /** Never throws: any failure comes back as a Result with ok=false. */
    public Result send(String number, String message, String senderId, boolean testMode) {
        try {
            // Empty log path: the library writes no log file inside the Keycloak server.
            KwtSMS client = new KwtSMS(username, password, senderId, testMode, "", APP_TOKEN);
            SendResult r = client.send(number, message);
            boolean ok = "OK".equals(r.getResult());
            String code = ok ? null : (r.getCode() != null ? r.getCode() : "NO_CODE");
            return new Result(ok, code, r.getMsgId());
        } catch (RuntimeException e) {
            return new Result(false, "EXCEPTION_" + e.getClass().getSimpleName(), null);
        }
    }

    /** Version from the jar manifest (Implementation-Version, set by build.gradle); "dev" in tests. */
    static String version() {
        String v = KwtsmsSender.class.getPackage().getImplementationVersion();
        return v == null || v.isEmpty() ? "dev" : v;
    }

    /** Outcome of one send; errorCode is a kwtSMS code such as ERR003, or a local code, never a secret. */
    public static final class Result {
        public final boolean ok;
        public final String errorCode;
        public final String msgId;

        public Result(boolean ok, String errorCode, String msgId) {
            this.ok = ok;
            this.errorCode = errorCode;
            this.msgId = msgId;
        }
    }
}
