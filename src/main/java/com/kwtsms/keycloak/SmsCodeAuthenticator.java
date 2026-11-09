/*
 * FILE:      src/main/java/com/kwtsms/keycloak/SmsCodeAuthenticator.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      The "kwtSMS SMS code" authenticator: sends a one-time code by SMS to the phone number in a user
 *            attribute, shows the code form (with a resend button), and checks the code.
 * WHY:       SMS second factor for Keycloak through a Kuwaiti gateway, with Arabic messages, abuse limits and
 *            fail-closed handling (one generic message to the user, details only in the server log and events).
 * USAGE:     Created by SmsCodeAuthenticatorFactory; added by an admin to a browser flow after the Username
 *            Password Form. Form fields: "kwtsms_code" (the code) and "resend" (button).
 * DEPENDS:   Keycloak 26.x server SPI (provided by the server), KwtsmsSender, StepSettings, SmsCode, HourlyCap,
 *            PhoneRules, MessageTemplate; template theme-resources/templates/kwtsms-sms-code.ftl;
 *            KeycloakSession.singleUseObjects() for the hourly caps (2026-11-09 23:37 +03, onyx-fixes #1176).
 *            2026-11-09 23:53 +03 (onyx-fixes #1176, N1): the client IP from context.getConnection() for the per-IP throttle.
 */
package com.kwtsms.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import org.keycloak.models.SingleUseObjectProvider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class SmsCodeAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(SmsCodeAuthenticator.class);

    static final String TEMPLATE = "kwtsms-sms-code.ftl";
    static final String FIELD_CODE = "kwtsms_code";
    static final String FIELD_RESEND = "resend";

    static final String NOTE_HASH = "kwtsms.code.hash";
    static final String NOTE_EXPIRES = "kwtsms.code.expires";
    static final String NOTE_SENT = "kwtsms.code.sent";
    static final String NOTE_ATTEMPTS = "kwtsms.code.attempts";
    static final String NOTE_LOCKED = "kwtsms.code.locked";

    // Message keys, theme-resources/messages/messages_<lang>.properties
    static final String MSG_SEND_FAILED = "kwtsmsSendFailed";
    static final String MSG_INVALID = "kwtsmsCodeInvalid";
    static final String MSG_EXPIRED = "kwtsmsCodeExpired";
    static final String MSG_TOO_MANY = "kwtsmsTooManyAttempts";
    static final String MSG_RESEND_WAIT = "kwtsmsResendWait";
    static final String MSG_RESENT = "kwtsmsCodeResent";

    /** 2026-11-09 23:53 +03 (onyx-fixes #1176, N1): fixed text of the error line to alert on; documented in README. Never change it. */
    static final String REALM_CEILING_LOG = "kwtSMS SMS code: realm SMS ceiling reached";

    private final KwtsmsSender sender;

    public SmsCodeAuthenticator(KwtsmsSender sender) {
        this.sender = sender;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        StepSettings s = settings(context);
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        if (isLocked(auth)) {
            failClosed(context, "locked");
            return;
        }
        long now = now();
        String hash = auth.getAuthNote(NOTE_HASH);
        // A page reload must not send another SMS: reuse a live code, or one still inside the resend wait.
        // 2026-11-09 23:53 +03 (onyx-fixes #1176, N2): the rule is SmsCode.keepCurrentCode, covered by SmsCodeTest.
        if (SmsCode.keepCurrentCode(hash != null, now, longNote(auth, NOTE_EXPIRES), longNote(auth, NOTE_SENT),
                s.resendWaitSeconds)) {
            context.challenge(form(context, s).createForm(TEMPLATE));
            return;
        }
        String reason = sendNewCode(context, s, now);
        if (reason != null) {
            failClosed(context, reason);
            return;
        }
        context.challenge(form(context, s).createForm(TEMPLATE));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        StepSettings s = settings(context);
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        if (isLocked(auth)) {
            failClosed(context, "locked");
            return;
        }
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        long now = now();

        if (params.containsKey(FIELD_RESEND)) {
            long waitLeft = SmsCode.resendWaitLeft(now, longNote(auth, NOTE_SENT), s.resendWaitSeconds);
            if (waitLeft > 0) {
                context.challenge(form(context, s).setError(MSG_RESEND_WAIT, Long.toString(waitLeft)).createForm(TEMPLATE));
                return;
            }
            String reason = sendNewCode(context, s, now);
            if (reason != null) {
                failClosed(context, reason);
                return;
            }
            context.challenge(form(context, s).setSuccess(MSG_RESENT).createForm(TEMPLATE));
            return;
        }

        String hash = auth.getAuthNote(NOTE_HASH);
        if (hash == null) {
            // No code in this session yet (for example a stale form): start the step again.
            authenticate(context);
            return;
        }

        int attempts = (int) longNote(auth, NOTE_ATTEMPTS) + 1;
        auth.setAuthNote(NOTE_ATTEMPTS, Integer.toString(attempts));

        if (SmsCode.isExpired(now, longNote(auth, NOTE_EXPIRES))) {
            context.getEvent().user(context.getUser()).detail("kwtsms_result", "expired").error(Errors.EXPIRED_CODE);
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                    form(context, s).setError(MSG_EXPIRED).createForm(TEMPLATE));
            return;
        }

        // 2026-11-09 23:37 +03 (onyx-fixes #1176, K5, K7): keyed hash, and input longer than the code is rejected.
        byte[] key = sender == null || !sender.hasCredentials() ? null : sender.codeKey();
        if (SmsCode.matches(params.getFirst(FIELD_CODE), hash, key, s.codeLength)) {
            clearCode(auth);
            auth.removeAuthNote(NOTE_ATTEMPTS);
            context.getEvent().detail("kwtsms_result", "verified");
            context.success();
            return;
        }

        if (attempts >= s.maxAttempts) {
            clearCode(auth);
            auth.setAuthNote(NOTE_LOCKED, "true");
            context.getEvent().user(context.getUser()).detail("kwtsms_result", "too_many_attempts")
                    .detail("kwtsms_attempts", Integer.toString(attempts)).error(Errors.INVALID_USER_CREDENTIALS);
            LOG.warnf("kwtSMS SMS code: too many attempts, realm=%s user=%s", context.getRealm().getName(),
                    context.getUser().getId());
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(MSG_TOO_MANY).createErrorPage(Response.Status.UNAUTHORIZED));
            return;
        }

        context.getEvent().user(context.getUser()).detail("kwtsms_result", "wrong_code")
                .detail("kwtsms_attempts", Integer.toString(attempts)).error(Errors.INVALID_USER_CREDENTIALS);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                form(context, s).setError(MSG_INVALID).createForm(TEMPLATE));
    }

    /**
     * Send a fresh code and store its hash, replacing any earlier one. Returns null on success, or a short
     * reason for the server log and events (never shown to the user).
     */
    String sendNewCode(AuthenticationFlowContext context, StepSettings s, long now) {
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        if (sender == null || !sender.hasCredentials()) return "no_api_credentials";
        if (s.senderId.isEmpty()) return "no_sender_id";

        String number = PhoneRules.resolve(user.getFirstAttribute(s.phoneAttribute), s.defaultCountryCode);
        if (number == null) {
            return user.getFirstAttribute(s.phoneAttribute) == null ? "no_phone" : "invalid_phone";
        }
        context.getEvent().detail("kwtsms_number", PhoneRules.mask(number));
        if (!PhoneRules.allowed(number, s.allowedCountryCodes)) return "country_not_allowed";

        // 2026-11-09 23:37 +03 (onyx-fixes #1176, K1, K2, K3): caps live in server-side storage, not in a user
        // attribute; a slot is claimed atomically BEFORE the send, so parallel logins cannot pass together.
        // 2026-11-09 23:53 +03 (onyx-fixes #1176, N1, N2): user, then client IP, then realm; the slots taken
        // are kept in `taken` so they can be given back when no SMS goes out.
        HourlyCap.Store store;
        try {
            store = store(context.getSession().singleUseObjects());
        } catch (RuntimeException e) {
            LOG.warnf("kwtSMS SMS code: SMS counter unavailable, realm=%s user=%s (%s); failing closed",
                    realm.getName(), user.getId(), e.getClass().getSimpleName());
            return "counter_unavailable";
        }
        List<String> taken = new ArrayList<>();
        String capped = takeSlots(store, realm, user, clientIp(context), s, now, taken);
        if (capped != null) return capped;

        KwtsmsSender.Result r;
        String code;
        try {
            code = SmsCode.generate(s.codeLength);
            Locale locale = context.getSession().getContext().resolveLocale(user);
            String realmName = realm.getDisplayName() != null && !realm.getDisplayName().isEmpty()
                    ? realm.getDisplayName() : realm.getName();
            String text = MessageTemplate.render(MessageTemplate.pick(locale, s.templateEn, s.templateAr), code,
                    SmsCode.ttlMinutes(s.ttlSeconds), realmName);
            r = sender.send(number, text, s.senderId, s.testMode);
        } catch (RuntimeException e) {
            // 2026-11-09 23:53 +03 (onyx-fixes #1176, N2): nothing was sent, give the slots back.
            giveBack(store, taken, now, realm);
            throw e;
        }
        if (!r.ok) {
            // 2026-11-09 23:53 +03 (onyx-fixes #1176, N2): a kwtSMS outage must not use up the hour's slots
            // and lock users out.
            // 2026-11-10 00:00 +03 (onyx-fixes #1176): give slots back only on a definite API refusal (ERRxxx: the
            // SMS was not sent). A timeout or connection error (EXCEPTION_*) may still have delivered it, so those
            // slots stay taken; otherwise retries during an outage would bypass the caps.
            if (r.errorCode != null && r.errorCode.startsWith("ERR")) giveBack(store, taken, now, realm);
            context.getEvent().detail("kwtsms_error", r.errorCode);
            LOG.warnf("kwtSMS SMS code: send failed, realm=%s user=%s number=%s error=%s", realm.getName(),
                    user.getId(), PhoneRules.mask(number), r.errorCode);
            return "send_error";
        }

        AuthenticationSessionModel auth = context.getAuthenticationSession();
        auth.setAuthNote(NOTE_HASH, SmsCode.hash(sender.codeKey(), code)); // 2026-11-09 23:37 +03 (onyx-fixes #1176, K5)
        auth.setAuthNote(NOTE_EXPIRES, Long.toString(now + s.ttlSeconds));
        auth.setAuthNote(NOTE_SENT, Long.toString(now));
        // 2026-11-09 23:37 +03 (onyx-fixes #1176, K1): the user attribute write (kwtsms_sms_sent) is gone; the slot
        // was taken in takeSlots before the send.

        context.getEvent().detail("kwtsms_result", "sent").detail("kwtsms_test_mode", Boolean.toString(s.testMode));
        if (r.msgId != null) context.getEvent().detail("kwtsms_msg_id", r.msgId);
        LOG.infof("kwtSMS SMS code: sent, realm=%s user=%s number=%s test=%s msg-id=%s", realm.getName(),
                user.getId(), PhoneRules.mask(number), s.testMode, r.msgId);
        return null;
    }

    /**
     * Claim one per-user slot, one per-client-IP slot and one realm slot of the current clock hour, in that order,
     * so one address that hits its own limit never reaches the realm ceiling. Returns null when all three are
     * taken for this SMS (their keys are in {@code taken}), or a reason; on a refusal no slot stays taken.
     * Fails closed: if the store throws, no SMS is sent.
     * 2026-11-09 23:37 +03 (onyx-fixes #1176, K1, K2, K3); 2026-11-09 23:53 +03 (onyx-fixes #1176, N1, N2): IP scope, release on refusal,
     * fixed realm ceiling log text.
     */
    static String takeSlots(HourlyCap.Store store, RealmModel realm, UserModel user, String ip, StepSettings s,
                            long now, List<String> taken) {
        String[] scopes = {HourlyCap.userScope(realm.getId(), user.getId()), HourlyCap.ipScope(realm.getId(), ip),
                HourlyCap.realmScope(realm.getId())};
        int[] max = {s.maxPerHour, s.maxPerIpHour, s.maxPerRealmHour};
        int refused;
        try {
            refused = HourlyCap.takeAll(store, scopes, max, now, taken);
        } catch (RuntimeException e) {
            LOG.warnf("kwtSMS SMS code: SMS counter unavailable, realm=%s user=%s (%s); failing closed",
                    realm.getName(), user.getId(), e.getClass().getSimpleName());
            return "counter_unavailable";
        }
        switch (refused) {
            case -1:
                return null;
            case 0:
                return "user_hourly_cap";
            case 1:
                LOG.warnf("kwtSMS SMS code: IP hourly SMS limit (%d) reached, realm=%s ip=%s", s.maxPerIpHour,
                        realm.getName(), ip);
                return "ip_hourly_cap";
            default:
                LOG.errorf("%s, realm=%s limit=%d; no more codes until the hour ends (%d s)", REALM_CEILING_LOG,
                        realm.getName(), s.maxPerRealmHour, HourlyCap.secondsLeft(now));
                return "realm_hourly_cap";
        }
    }

    /**
     * Release the slots of an SMS that was not sent; a store error only leaves them taken.
     * 2026-11-09 23:53 +03 (onyx-fixes #1176, N2).
     */
    private static void giveBack(HourlyCap.Store store, List<String> taken, long now, RealmModel realm) {
        int failed = HourlyCap.releaseAll(store, taken, now);
        if (failed > 0) {
            LOG.warnf("kwtSMS SMS code: %d SMS slot(s) could not be released, realm=%s; they free up when the hour "
                    + "ends", failed, realm.getName());
        }
    }

    /**
     * The client address Keycloak sees. Behind a reverse proxy it is the proxy's address unless Keycloak's
     * proxy-headers option is set. 2026-11-09 23:53 +03 (onyx-fixes #1176, N1).
     */
    private static String clientIp(AuthenticationFlowContext context) {
        try {
            return context.getConnection() == null ? null : context.getConnection().getRemoteAddr();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Keycloak's SingleUseObjectProvider as the cap store: users cannot read or edit it, it does not touch user
     * storage (works for LDAP and other federated users), and on Infinispan putIfAbsent is a single cluster-wide
     * operation. Keys never end in ".revoked", so the revoked-token persister is never involved.
     * 2026-11-09 23:37 +03 (onyx-fixes #1176, K1, K2).
     */
    static HourlyCap.Store store(SingleUseObjectProvider p) {
        if (p == null) throw new IllegalStateException("no SingleUseObjectProvider");
        return new HourlyCap.Store() {
            @Override
            public boolean claim(String key, long lifespanSeconds) {
                return p.putIfAbsent(key, lifespanSeconds);
            }

            @Override
            public String read(String key) {
                Map<String, String> m = p.get(key);
                return m == null ? null : m.get("n");
            }

            // 2026-11-09 23:53 +03 (onyx-fixes #1176, N2): give back a slot of an SMS that was not sent.
            @Override
            public void release(String key) {
                p.remove(key);
            }

            @Override
            public void write(String key, String value, long lifespanSeconds) {
                p.put(key, lifespanSeconds, Collections.singletonMap("n", value));
            }
        };
    }

    /**
     * One generic message for every send problem (no account enumeration); the reason goes to logs and events.
     * 2026-11-09 23:37 +03 (onyx-fixes #1176, K3): a soft stop. It used to be failure(), which Keycloak counts as a
     * failed login for brute-force detection, so someone with a stolen password could get the real user locked
     * out. Now it is a challenge: the error page is shown, nothing is counted, and the step is tried again on the
     * next request (a capped user can log in once the hour ends, never later). Wrong codes still count.
     */
    private void failClosed(AuthenticationFlowContext context, String reason) {
        // A challenge does not write an error event itself, so write it here.
        context.getEvent().user(context.getUser()).detail("kwtsms_result", "failed").detail("kwtsms_reason", reason)
                .error(Errors.GENERIC_AUTHENTICATION_ERROR);
        LOG.warnf("kwtSMS SMS code: failed closed, realm=%s user=%s reason=%s", context.getRealm().getName(),
                context.getUser() == null ? "(none)" : context.getUser().getId(), reason);
        context.challenge(context.form().setError(MSG_SEND_FAILED).createErrorPage(Response.Status.BAD_REQUEST));
    }

    private LoginFormsProvider form(AuthenticationFlowContext context, StepSettings s) {
        return context.form()
                .setAttribute("kwtsmsCodeLength", s.codeLength)
                .setAttribute("kwtsmsTestMode", s.testMode);
    }

    private static StepSettings settings(AuthenticationFlowContext context) {
        AuthenticatorConfigModel cfg = context.getAuthenticatorConfig();
        return StepSettings.from(cfg == null ? null : cfg.getConfig());
    }

    private static boolean isLocked(AuthenticationSessionModel auth) {
        return "true".equals(auth.getAuthNote(NOTE_LOCKED));
    }

    private static void clearCode(AuthenticationSessionModel auth) {
        auth.removeAuthNote(NOTE_HASH);
        auth.removeAuthNote(NOTE_EXPIRES);
    }

    private static long longNote(AuthenticationSessionModel auth, String key) {
        String v = auth.getAuthNote(key);
        if (v == null) return 0;
        try {
            return Long.parseLong(v);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static long now() {
        return System.currentTimeMillis() / 1000L;
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    /**
     * Always true: a user without a usable phone number is handled inside the step (fail closed with the
     * generic message) instead of letting Keycloak skip or abort the step with a different error.
     */
    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // v0.1 has no required action; the phone number comes from the user attribute set by an admin or LDAP.
    }

    @Override
    public void close() {
    }
}
