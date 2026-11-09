/*
 * FILE:      src/main/java/com/kwtsms/keycloak/MessageTemplate.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      Picks the English or Arabic SMS template by locale and fills {code}, {ttl_minutes} and {realm}.
 * WHY:       Users whose Keycloak locale is Arabic get the SMS in Arabic; everyone else gets English.
 * USAGE:     String t = MessageTemplate.pick(locale, s.templateEn, s.templateAr);
 *            String sms = MessageTemplate.render(t, code, 5, "My Realm");
 * DEPENDS:   Java 17 only.
 */
package com.kwtsms.keycloak;

import java.util.Locale;

public final class MessageTemplate {

    private MessageTemplate() {
    }

    /** Arabic template when the locale language starts with "ar", else English. */
    public static String pick(Locale locale, String templateEn, String templateAr) {
        return isArabic(locale) ? templateAr : templateEn;
    }

    public static boolean isArabic(Locale locale) {
        return locale != null && locale.getLanguage() != null
                && locale.getLanguage().toLowerCase(Locale.ROOT).startsWith("ar");
    }

    /**
     * Replace the placeholders. The code is inserted last so a realm name that contains "{code}" cannot
     * repeat or move the code.
     */
    public static String render(String template, String code, int ttlMinutes, String realm) {
        String t = template == null ? "" : template;
        String r = realm == null ? "" : realm.replace("{code}", "");
        return t.replace("{ttl_minutes}", Integer.toString(ttlMinutes))
                .replace("{realm}", r)
                .replace("{code}", code);
    }
}
