# O365 - Security And Compliance - Content Search

This integration is administrative interface that enables you to manage the features that are available in the Security & Compliance Center from the XSOAR.

Supported authentication methods:

1. Basic authentication - Fill UPN and Password.
2. OAuth2.0 (For MFA enabled accounts) -
    a. Fill UPN parameter in integration configuration.
    b. Run command !o365-sc-start-auth and follow the instructions.
    c. For testing completion of authoriztion process run command !o365-sc-test-auth.