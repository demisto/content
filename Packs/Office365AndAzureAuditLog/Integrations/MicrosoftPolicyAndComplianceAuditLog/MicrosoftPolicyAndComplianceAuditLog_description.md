### Ews Audit Log
This integration searches the unified audit log to view user and administrator activity in your organization.

Supported authentication methods:

- Basic authentication - Fill in the email and password.
- OAuth2.0 (For MFA enabled accounts) -
    1. Enter a value for the UPN parameter in the integration configuration.
    2. Run the ***o365-auditlog-auth-start*** command and follow the instructions.
    3. Run the ***o365-auditlog-auth-test*** command to verify that the authorization process was implemented correctly.
  
#### Permissions:
The app uses the *https://outlook.office365.com/.default* scope.
