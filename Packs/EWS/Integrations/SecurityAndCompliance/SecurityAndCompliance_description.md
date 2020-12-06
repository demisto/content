# O365 - Security And Compliance - Content Search

This integration enables you to manage the features that are available in the Security & Compliance Center from XSOAR.

Supported authentication methods:

- Basic authentication - Fill in the UPN and password.
- OAuth2.0 (For MFA enabled accounts) -
    1. Fill in the UPN parameter in the integration configuration.
    2. Run the ***o365-sc-auth-start*** command and follow the instructions.
    3. For testing completion of authorization process run the ***o365-sc-auth-test*** command.
