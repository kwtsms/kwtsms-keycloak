# Changelog

## [Unreleased]

## [0.1.0] - 2026-11-09

### Added
- "kwtSMS SMS code" login step for Keycloak 26: a one-time code sent by SMS to the phone number stored on the user.
- Code page in English and Arabic with a Resend code button; SMS text in English or Arabic by the user's language.
- Limits: code lifetime, resend wait, wrong-code attempts, SMS per user per hour, SMS per realm per hour and allowed
  country codes.
- Test mode for trying the step without delivering messages.

### Security
- Hourly SMS limits are kept on the Keycloak server, shared by all cluster nodes, instead of in the user attribute
  `kwtsms_sms_sent`. They work with LDAP and other read-only user stores, users cannot reset them, and parallel
  logins cannot pass them. The `kwtsms_sms_sent` attribute is no longer used.
- New realm-wide limit, Max SMS per realm per hour (default 200). When it is reached the server log shows a fixed
  line to alert on: `kwtSMS SMS code: realm SMS ceiling reached`.
- New limit per client IP address, Max SMS per IP per hour (default 100), so one address cannot use up the realm
  limit. IPv6 addresses count by their /64 network. README: notes for mobile networks (many users on one address)
  and for setting Keycloak's `proxy-headers` option behind a reverse proxy.
- A send that kwtSMS refuses (an error reply) no longer uses up hourly limits. A timeout still counts, because the SMS may have gone out.
- A failed send starts the resend wait, so reloading the page right after it does not try another SMS.
- A user who reaches the hourly limit can log in again when the hour ends; sending problems no longer count as
  failed logins.
- Allowed country codes need an explicit list; `*` (every country) is no longer accepted.
- The step can be Required or Disabled; Alternative was removed.
- Codes are stored with a keyed hash, too-long code input is rejected, and the mobile number is masked more in logs.
- Build dependencies and the Gradle download are checked against pinned checksums.
- README: the phone attribute must be editable by admins only, and brute force detection should be on.
