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
 *            PhoneRules, MessageTemplate; template theme-resources/templates/kwtsms-sms-code.ftl.
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

import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

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
        if (hash != null) {
            boolean expired = SmsCode.isExpired(now, longNote(auth, NOTE_EXPIRES));
            long waitLeft = SmsCode.resendWaitLeft(now, longNote(auth, NOTE_SENT), s.resendWaitSeconds);
            // A page reload must not send another SMS: reuse a live code, or one still inside the resend wait.
            if (!expired || waitLeft > 0) {
                context.challenge(form(context, s).createForm(TEMPLATE));
                return;
            }
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

        if (SmsCode.matches(params.getFirst(FIELD_CODE), hash)) {
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

        List<Long> recent = HourlyCap.trim(user.getAttributeStream(HourlyCap.ATTRIBUTE).collect(Collectors.toList()), now);
        if (!HourlyCap.allowed(recent, s.maxPerHour)) return "hourly_cap";

        String code = SmsCode.generate(s.codeLength);
        Locale locale = context.getSession().getContext().resolveLocale(user);
        String realmName = realm.getDisplayName() != null && !realm.getDisplayName().isEmpty()
                ? realm.getDisplayName() : realm.getName();
        String text = MessageTemplate.render(MessageTemplate.pick(locale, s.templateEn, s.templateAr), code,
                SmsCode.ttlMinutes(s.ttlSeconds), realmName);

        KwtsmsSender.Result r = sender.send(number, text, s.senderId, s.testMode);
        if (!r.ok) {
            context.getEvent().detail("kwtsms_error", r.errorCode);
            LOG.warnf("kwtSMS SMS code: send failed, realm=%s user=%s number=%s error=%s", realm.getName(),
                    user.getId(), PhoneRules.mask(number), r.errorCode);
            return "send_error";
        }

        AuthenticationSessionModel auth = context.getAuthenticationSession();
        auth.setAuthNote(NOTE_HASH, SmsCode.hash(code));
        auth.setAuthNote(NOTE_EXPIRES, Long.toString(now + s.ttlSeconds));
        auth.setAuthNote(NOTE_SENT, Long.toString(now));

        recent.add(now);
        try {
            user.setAttribute(HourlyCap.ATTRIBUTE, HourlyCap.toStrings(recent));
        } catch (RuntimeException e) {
            // Read-only user storage (for example LDAP): the resend wait and attempt limit still apply.
            LOG.warnf("kwtSMS SMS code: could not store the hourly counter for user=%s (%s)", user.getId(),
                    e.getClass().getSimpleName());
        }

        context.getEvent().detail("kwtsms_result", "sent").detail("kwtsms_test_mode", Boolean.toString(s.testMode));
        if (r.msgId != null) context.getEvent().detail("kwtsms_msg_id", r.msgId);
        LOG.infof("kwtSMS SMS code: sent, realm=%s user=%s number=%s test=%s msg-id=%s", realm.getName(),
                user.getId(), PhoneRules.mask(number), s.testMode, r.msgId);
        return null;
    }

    /** One generic message for every send problem (no account enumeration); the reason goes to logs and events. */
    private void failClosed(AuthenticationFlowContext context, String reason) {
        // failure() with a response does not write an error event itself (DefaultAuthenticationFlow), so write it here.
        context.getEvent().user(context.getUser()).detail("kwtsms_result", "failed").detail("kwtsms_reason", reason)
                .error(Errors.GENERIC_AUTHENTICATION_ERROR);
        LOG.warnf("kwtSMS SMS code: failed closed, realm=%s user=%s reason=%s", context.getRealm().getName(),
                context.getUser() == null ? "(none)" : context.getUser().getId(), reason);
        context.failure(AuthenticationFlowError.INTERNAL_ERROR,
                context.form().setError(MSG_SEND_FAILED).createErrorPage(Response.Status.BAD_REQUEST));
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
