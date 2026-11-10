# Security

Report a vulnerability to support@kwtsms.com (subject: "kwtsms-keycloak security"). Please do not open a public issue.

Supported: the latest release.

This extension adds a second login step that sends a code by SMS. Codes are random, kept only as a keyed hash in the
login session, single use and short lived. Sending is limited per user, per IP address and per realm, and the kwtSMS
API password is read from the Keycloak server configuration, never from the admin console. See the README sections
"Limits and stolen passwords" and "Behind a reverse proxy or load balancer".
