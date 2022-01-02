## O365 Defender Safe Links

Supported authentication methods:

- Basic authentication - Fill in the email and password.
- OAuth2.0 (For MFA enabled accounts) -
    1. Enter a value for the UPN parameter in the integration configuration.
    2. Run the ***o365-auditlog-auth-start*** command and follow the instructions.
    3. Run the ***o365-auditlog-auth-test*** command to verify that the authorization process was implemented correctly.

#### Required Permissions
* The app uses the *https://outlook.office365.com/.default* scope.
* To create, modify, and delete Safe Links policies, you need to be a member of the `Organization Management` or `Security Administrator` role groups.
* To manage permissions in the Microsoft 365 Defender portal, go to `Permissions & roles` or https://security.microsoft.com/securitypermissions. You need to be a global administrator or a member of the Organization Management role group in the Microsoft 365 Defender portal. Specifically, the Role Management role allows users to view, create, and modify role groups in the Microsoft 365 Defender portal, and by default, that role is assigned only to the Organization Management role group.
* See [Permissions in the Microsoft 365 Defender portal](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/permissions-microsoft-365-security-center?view=o365-worldwide) for more information.
