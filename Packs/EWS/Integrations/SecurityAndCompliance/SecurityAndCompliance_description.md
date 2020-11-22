# O365 - Security And Compliance - Content Search

This integration enables you to manage the features that are available in the Security & Compliance Center from XSOAR.

Supported authentication methods:

- Basic authentication - Fill in the UPN and password.
- OAuth2.0 (For MFA enabled accounts) -
    1. Fill in the UPN parameter in the integration configuration.
    2. Run the ***o365-sc-start-auth*** command and follow the instructions.
    3. To test the completion of the authoriztion process, run the ***o365-sc-test-auth*** command.
