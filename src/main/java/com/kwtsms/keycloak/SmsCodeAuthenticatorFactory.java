/*
 * FILE:      src/main/java/com/kwtsms/keycloak/SmsCodeAuthenticatorFactory.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      Registers the "kwtSMS SMS code" authenticator (id kwtsms-sms-code) with Keycloak: requirement
 *            choices, the step settings shown in the admin console, and the kwtSMS API username and password
 *            read from the provider SPI config (never from the step config).
 * WHY:       Keycloak finds authenticators through AuthenticatorFactory implementations listed in
 *            META-INF/services/org.keycloak.authentication.AuthenticatorFactory.
 * USAGE:     Server options (CLI, keycloak.conf or environment):
 *              --spi-authenticator--kwtsms-sms-code--username=...   KC_SPI_AUTHENTICATOR__KWTSMS_SMS_CODE__USERNAME
 *              --spi-authenticator--kwtsms-sms-code--password=...   KC_SPI_AUTHENTICATOR__KWTSMS_SMS_CODE__PASSWORD
 * DEPENDS:   Keycloak 26.x server SPI (provided by the server), SmsCodeAuthenticator, KwtsmsSender, StepSettings.
 */
package com.kwtsms.keycloak;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

public class SmsCodeAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "kwtsms-sms-code";

    /** Property names inside the SPI scope spi-authenticator--kwtsms-sms-code. */
    static final String SPI_USERNAME = "username";
    static final String SPI_PASSWORD = "password";

    private static final Logger LOG = Logger.getLogger(SmsCodeAuthenticatorFactory.class);

    // 2026-11-09 23:37 +03 (onyx-fixes #1176, K11): ALTERNATIVE removed. Next to other factors it made SMS the
    // weakest choice, and a user without a phone failed instead of being skipped. Use Required after the password.
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENTS = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    private static final List<ProviderConfigProperty> CONFIG = ProviderConfigurationBuilder.create()
            .property().name(StepSettings.SENDER_ID).label("Sender ID")
            .helpText("Your kwtSMS Sender ID for these messages. Use a Transactional Sender ID: promotional ones "
                    + "are filtered for numbers on the do-not-disturb list. Required.")
            .type(ProviderConfigProperty.STRING_TYPE).add()
            .property().name(StepSettings.PHONE_ATTRIBUTE).label("Phone attribute")
            .helpText("User attribute that holds the mobile number (for LDAP or Active Directory often 'mobile').")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(StepSettings.DEF_PHONE_ATTRIBUTE).add()
            .property().name(StepSettings.DEFAULT_COUNTRY_CODE).label("Default country code")
            .helpText("Added in front of local numbers of 8 digits or fewer written without + or 00.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(StepSettings.DEF_COUNTRY_CODE).add()
            .property().name(StepSettings.ALLOWED_COUNTRY_CODES).label("Allowed country codes")
            // 2026-11-09 23:37 +03 (onyx-fixes #1176, K4): no "*" any more; an explicit list is required.
            .helpText("Comma separated, for example 965 or 965, 966. Codes are sent only to numbers that start with "
                    + "one of these. There is no 'all countries' value: an empty list sends no codes.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(StepSettings.DEF_ALLOWED).add()
            .property().name(StepSettings.CODE_LENGTH).label("Code length")
            .helpText("Digits in the SMS code, 4 to 10.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(Integer.toString(StepSettings.DEF_CODE_LENGTH)).add()
            .property().name(StepSettings.CODE_TTL).label("Code lifetime (seconds)")
            .helpText("How long a code can be used, 60 to 3600 seconds.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(Integer.toString(StepSettings.DEF_TTL)).add()
            .property().name(StepSettings.RESEND_WAIT).label("Resend wait (seconds)")
            .helpText("Time before the user can ask for a new code, 30 to 3600 seconds.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(Integer.toString(StepSettings.DEF_RESEND_WAIT)).add()
            .property().name(StepSettings.MAX_ATTEMPTS).label("Max attempts")
            .helpText("Wrong codes allowed in one login before the login fails, 1 to 10.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(Integer.toString(StepSettings.DEF_MAX_ATTEMPTS)).add()
            .property().name(StepSettings.MAX_PER_HOUR).label("Max SMS per user per hour")
            // 2026-11-09 23:37 +03 (onyx-fixes #1176, K3): counted per clock hour in server storage.
            .helpText("SMS codes one user can receive in one clock hour, 1 to 50. A user who reaches it can log in "
                    + "again when the hour ends.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(Integer.toString(StepSettings.DEF_MAX_PER_HOUR)).add()
            // 2026-11-09 23:37 +03 (onyx-fixes #1176, K3): realm-wide ceiling against cost from many stolen passwords.
            .property().name(StepSettings.MAX_PER_REALM_HOUR).label("Max SMS per realm per hour")
            .helpText("SMS codes the whole realm can send in one clock hour, all users together, 1 to 10000. "
                    + "When it is reached nobody gets a code until the hour ends; the server log says so.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(Integer.toString(StepSettings.DEF_MAX_PER_REALM_HOUR)).add()
            // 2026-11-09 23:53 +03 (onyx-fixes #1176, N1): per-IP throttle so one address cannot use up the realm ceiling.
            .property().name(StepSettings.MAX_PER_IP_HOUR).label("Max SMS per IP per hour")
            .helpText("SMS codes one client IP address can get in one clock hour, all users together, 1 to 10000. "
                    + "Behind a reverse proxy, set Keycloak's proxy-headers option so this is the real client IP. "
                    // 2026-11-10 00:07 +03 (onyx-fixes #1176, C1, C3): CGNAT hint and the IPv6 /64 key.
                    + "Mobile networks put many customers on one address: for a public consumer realm use 200 to 500. "
                    + "IPv6 clients are counted by their /64 network.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(Integer.toString(StepSettings.DEF_MAX_PER_IP_HOUR)).add()
            .property().name(StepSettings.TEST_MODE).label("Test mode")
            .helpText("Warning: in test mode messages are NOT delivered, so users cannot log in. kwtSMS queues "
                    + "them and holds their credits until you delete them from the Sending Queue. For testing only.")
            .type(ProviderConfigProperty.BOOLEAN_TYPE).defaultValue("false").add()
            .property().name(StepSettings.TEMPLATE_EN).label("SMS template (English)")
            .helpText("Placeholders: {code} {ttl_minutes} {realm}.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(StepSettings.DEF_TEMPLATE_EN).add()
            .property().name(StepSettings.TEMPLATE_AR).label("SMS template (Arabic)")
            .helpText("Used when the user's language is Arabic. Placeholders: {code} {ttl_minutes} {realm}.")
            .type(ProviderConfigProperty.STRING_TYPE).defaultValue(StepSettings.DEF_TEMPLATE_AR).add()
            .build();

    private KwtsmsSender sender = new KwtsmsSender(null, null);

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new SmsCodeAuthenticator(sender);
    }

    /** Reads the API login from the SPI config. Values are never logged, only whether they are set. */
    @Override
    public void init(Config.Scope config) {
        String username = config == null ? null : config.get(SPI_USERNAME);
        String password = config == null ? null : config.get(SPI_PASSWORD);
        sender = new KwtsmsSender(username, password);
        if (!sender.hasCredentials()) {
            LOG.warn("kwtSMS SMS code: API username or password not set "
                    + "(spi-authenticator--kwtsms-sms-code--username / --password); the step will fail closed.");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getDisplayType() {
        return "kwtSMS SMS code";
    }

    @Override
    public String getReferenceCategory() {
        return "kwtsms-sms-code";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENTS;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Sends a one-time code by SMS through kwtSMS to the phone number in a user attribute and asks for it.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG;
    }
}
