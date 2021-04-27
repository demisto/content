### Safe Links Statistics
This integration searches the Safe Links statistics from your Office365 subscription.

Supported authentication methods:

- Basic authentication - Fill in the email and password.
- OAuth2.0 (For MFA enabled accounts) -
    1. Enter a value for the UPN parameter in the integration configuration.
    2. Run the ***o365-safelinks-auth-start*** command and follow the instructions.
    3. Run the ***o365-safelinks-auth-complete** command to complete the authentication
    4. Run the ***o365-safelinks-auth-test*** command to verify that the authorization process was implemented correctly.
  
#### Permissions:
The app uses the *https://outlook.office365.com/.default* scope.


---
