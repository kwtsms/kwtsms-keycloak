<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/readme-header-dark.png">
  <img alt="kwtSMS: SMS gateway for Kuwait" src=".github/assets/readme-header-light.png">
</picture>

# kwtSMS for Keycloak

[![Keycloak](https://img.shields.io/badge/Keycloak-26.x-4d4d4d)](https://www.keycloak.org)
[![Java](https://img.shields.io/badge/Java-17%2B-007396)](https://adoptium.net)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/license/mit)

Add an SMS code to your Keycloak logins: after the password, Keycloak sends a one-time code by SMS through kwtSMS,
the Kuwaiti SMS gateway, and the user types it in. Free and open source.

kwtSMS delivers to Zain, Ooredoo, stc and Virgin in Kuwait and to more than 200 countries, with your own Sender ID,
free API testing and credits that do not expire.

## Features

**Login step**
- "kwtSMS SMS code" step for any browser flow, usually right after the Username Password Form.
- The code goes to the mobile number stored on the user (attribute `phone_number`, or any attribute you choose,
  for example `mobile` from LDAP or Active Directory).
- Code page with a Resend code button, in English and Arabic.
- SMS text in English or Arabic, chosen by the user's language, with `{code}`, `{ttl_minutes}` and `{realm}`.

**Security**
- Random codes, kept only as a hash, single use, with a lifetime you set.
- Limits: wrong-code attempts per login, resend wait, SMS per user per hour, allowed country codes.
- One general message to the user for every sending problem; the reason is written to the server log and to
  Keycloak events, with the mobile number masked.
- The kwtSMS API password is set on the server, never in the admin console.

## Requirements

- Keycloak 26.x (built and tested against 26.8.2), Java 17 or later.
- A kwtSMS account (free test account, no papers): https://www.kwtsms.com/cportal/signup/
- A Transactional Sender ID for login codes (promotional Sender IDs are filtered for numbers on the
  do-not-disturb list).

## Installation

1. Download `kwtsms-keycloak-<version>.jar` from the releases page.
2. Copy it to the `providers/` folder of your Keycloak.
3. Run `bin/kc.sh build`, then restart Keycloak (`bin/kc.sh start`).

The jar is a single file: it carries everything it needs and nothing that Keycloak already has.

## Setup

### 1. API username and password (on the server)

Set the API username and password of your kwtSMS account (not your mobile number) as Keycloak server options.
Pick one of these ways:

```bash
# Command line
bin/kc.sh start \
  --spi-authenticator--kwtsms-sms-code--username=YOUR_API_USERNAME \
  --spi-authenticator--kwtsms-sms-code--password=YOUR_API_PASSWORD
```

```bash
# Environment variables (containers)
KC_SPI_AUTHENTICATOR__KWTSMS_SMS_CODE__USERNAME=YOUR_API_USERNAME
KC_SPI_AUTHENTICATOR__KWTSMS_SMS_CODE__PASSWORD=YOUR_API_PASSWORD
```

```properties
# conf/keycloak.conf
spi-authenticator--kwtsms-sms-code--username=YOUR_API_USERNAME
spi-authenticator--kwtsms-sms-code--password=YOUR_API_PASSWORD
```

If they are missing, the server log says so at start and the step refuses every login it is part of.

### 2. The phone number of each user

Each user needs a mobile number in a user attribute (default `phone_number`). In Keycloak 26 add the attribute in
**Realm settings > User profile** (or map it from LDAP), then fill it in for your users. Local numbers of 8 digits
or fewer get the default country code (`965`); numbers with `+` or `00` are used as they are.

### 3. The login flow

1. Go to **Authentication**, open the **browser** flow and choose **Duplicate**.
2. In the copy, find the step group that holds **Username Password Form** and click **Add step** there.
3. Choose **kwtSMS SMS code**, place it after **Username Password Form** and set it to **Required**.
4. Click the gear icon of the new step and fill in the settings (below). The Sender ID is required.
5. Use **Bind flow** on your copy and choose **Browser flow**.

### 4. Settings

| Setting | Default | Notes |
|---|---|---|
| Sender ID | (empty) | Required. Your Transactional Sender ID. |
| Phone attribute | `phone_number` | User attribute with the mobile number. |
| Default country code | `965` | For local numbers. |
| Allowed country codes | `965` | Comma separated; `*` allows every country (not recommended). |
| Code length | 6 | 4 to 10 digits. |
| Code lifetime (seconds) | 300 | 60 to 3600. |
| Resend wait (seconds) | 180 | 30 to 3600. |
| Max attempts | 5 | Wrong codes per login before the login fails. |
| Max SMS per user per hour | 5 | 1 to 50. |
| Test mode | off | Messages are queued, not delivered. |
| SMS template (English) | `Your {realm} SMS code is {code}. It expires in {ttl_minutes} minutes.` | |
| SMS template (Arabic) | `رمز التحقق لدخول {realm}: {code}، صالح لمدة {ttl_minutes} دقائق.` | Used for users whose language is Arabic. |

### Test mode

Turn test mode on to check your setup without delivering messages. Test messages are not delivered, so nobody can
log in through the step while it is on. Their credits are held until you delete them from the Sending Queue in your
kwtSMS account. Turn test mode off before real users log in.

## Arabic

The code page and its messages come in English and Arabic; Keycloak shows Arabic right to left when the user's
language is Arabic. Arabic SMS are sent as Unicode: one SMS page holds 70 Arabic characters, against 160 English
ones. Codes typed with Arabic digits are accepted.

## FAQ

**Which username do I use?** The API username and password of your kwtSMS account, not your mobile number.

**Why do test messages not arrive?** Test mode queues messages without delivering them. Turn it off in the step
settings.

**What is a Sender ID?** The name shown as the sender on the phone. See the
[Sender ID help](https://www.kwtsms.com/sender-id-help.html).

**A user says the code never came.** The user sees one general message on purpose. Look in the Keycloak server log
for `kwtSMS SMS code` and in the login events for the `kwtsms_reason` and `kwtsms_error` details: no phone number,
a number outside the allowed country codes, the hourly limit, or a kwtSMS error code.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Support

Help: https://www.kwtsms.com/support.html | FAQ: https://www.kwtsms.com/faq/ |
API: [developers](https://www.kwtsms.com/developers.html), [API reference](https://www.kwtsms.com/api-documentation.html)

## License

MIT, (c) kwtSMS (BoxLink Center). Includes the kwtSMS Java client library (MIT, (c) kwtSMS).
