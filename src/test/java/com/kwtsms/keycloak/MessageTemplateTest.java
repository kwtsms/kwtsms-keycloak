/*
 * FILE:      src/test/java/com/kwtsms/keycloak/MessageTemplateTest.java
 * CREATED:   2026-11-09 17:13 +03
 * TASK:      int-new W4
 * AUTHOR:    M Alhassoun
 * WHAT:      Unit tests for picking the English or Arabic template by locale and filling the placeholders.
 * WHY:       The security rules of the SMS code step must hold without a running Keycloak; no network.
 * USAGE:     ./gradlew test
 * DEPENDS:   JUnit 5.
 */
package com.kwtsms.keycloak;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

class MessageTemplateTest {

    @Test
    void picksArabicForArLocales() {
        assertEquals("AR", MessageTemplate.pick(new Locale("ar"), "EN", "AR"));
        assertEquals("AR", MessageTemplate.pick(Locale.forLanguageTag("ar-KW"), "EN", "AR"));
        assertEquals("EN", MessageTemplate.pick(Locale.ENGLISH, "EN", "AR"));
        assertEquals("EN", MessageTemplate.pick(Locale.forLanguageTag("fr"), "EN", "AR"));
        assertEquals("EN", MessageTemplate.pick(null, "EN", "AR"));
    }

    @Test
    void rendersDefaultEnglish() {
        String s = MessageTemplate.render(StepSettings.DEF_TEMPLATE_EN, "042917", 5, "Acme");
        assertEquals("Your Acme SMS code is 042917. It expires in 5 minutes.", s);
    }

    @Test
    void rendersDefaultArabic() {
        String s = MessageTemplate.render(StepSettings.DEF_TEMPLATE_AR, "042917", 5, "Acme");
        assertEquals("رمز التحقق لدخول Acme: 042917. مدة الصلاحية (بالدقائق): 5", s);
    }

    @Test
    void realmCannotInjectTheCode() {
        String s = MessageTemplate.render("{realm} {code}", "1234", 5, "x{code}y");
        assertEquals("xy 1234", s);
    }

    @Test
    void defaultTemplatesUseOnlySafeCharacters() {
        // No em dash, en dash, smart quotes or ellipsis: they force UCS-2 and double the SMS cost.
        for (String t : new String[]{StepSettings.DEF_TEMPLATE_EN, StepSettings.DEF_TEMPLATE_AR}) {
            assertFalse(t.matches(".*[\u2013\u2014\u2018\u2019\u201C\u201D\u2026].*"), t);
        }
        assertTrue(StepSettings.DEF_TEMPLATE_EN.chars().allMatch(c -> c < 128));
    }
}
