# O365 - Security And Compliance - Content Search V2

This integration enables you to manage the features that are available in the Security & Compliance Center from XSOAR.

Supported authentication methods:
- Delegated Authentication

### Important Notice Regarding MFA Enabled Service Accounts:
When MFA is enabled, it is possible to be unable to confirm a sign in as safe. The error message will still contain a correlation ID which can be queried. In this case, there are two separate options to enable the service account to work with the integration.

1. If there is a conditional access policy in place which will trigger a users account to require an MFA sign in, these policies should exempt the user which is used by the integration. This does _not_ require MFA to be disabled.
2. Disable MFA for the specific user.