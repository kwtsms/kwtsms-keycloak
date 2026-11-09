<#--
FILE:      src/main/resources/theme-resources/templates/kwtsms-sms-code.ftl
CREATED:   2026-11-09 17:13 +03
TASK:      int-new W4
AUTHOR:    M Alhassoun
WHAT:      Login page that asks for the SMS code, with a Sign In button and a Resend code button.
WHY:       Rendered by SmsCodeAuthenticator through context.form().createForm(); theme-resources/templates in a
           provider jar are available to every login theme. Written with the base template macros and kc* classes
           so it works with the keycloak and keycloak.v2 login themes; RTL comes from the theme for Arabic.
USAGE:     Fields posted to url.loginAction: kwtsms_code (the code) or resend (button).
DEPENDS:   template.ftl of the active login theme; messages kwtsms* in theme-resources/messages.
-->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        ${msg("kwtsmsCodeTitle")}
    <#elseif section = "form">
        <form id="kwtsms-sms-code-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="kwtsms_code" class="${properties.kcLabelClass!}">${msg("kwtsmsCodeLabel")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input id="kwtsms_code" name="kwtsms_code" type="text" class="${properties.kcInputClass!}"
                           inputmode="numeric" autocomplete="one-time-code" dir="ltr" autofocus
                           maxlength="${(kwtsmsCodeLength!6)?c}" />
                </div>
                <p class="${properties.kcFormHelperTextClass!}">${msg("kwtsmsCodeHelp")}</p>
            </div>
            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           name="login" id="kc-login" type="submit" value="${msg("doLogIn")}" />
                </div>
            </div>
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!(properties.kcButtonDefaultClass!"")} ${properties.kcButtonBlockClass!}"
                           name="resend" id="kwtsms-resend" type="submit" formnovalidate value="${msg("kwtsmsResend")}" />
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
