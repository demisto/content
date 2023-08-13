# O365 - Security And Compliance - Content Search V2

This integration enables you to manage the features that are available in the Security & Compliance Center from XSOAR.

For this integration, the UPN/Email is the account you wish to use in order to interface with Security & Compliance. 
The account may require additional permissions and roles associated with it in order to execute all commands. 
Please refer to the [documentation](https://xsoar.pan.dev/docs/reference/integrations/security-and-compliance-v2#authentication) for additional information.

Supported authentication methods:
- OAuth2.0 (For MFA enabled accounts) -
    1. Fill in the UPN parameter in the integration configuration.
    2. Run the ***o365-sc-auth-start*** command and follow the instructions.
    3. For testing completion of authorization process run the ***o365-sc-auth-test*** command.
