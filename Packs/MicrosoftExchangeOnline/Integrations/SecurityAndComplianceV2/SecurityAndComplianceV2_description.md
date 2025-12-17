# O365 - Security And Compliance - Content Search V2

This integration enables you to manage the features that are available in the Security & Compliance Center from XSOAR.

This integration supports two authentication methods:

- **App-only authentication**
- **Delegated user authentication**

Depending on the selected authentication method, you may need to create a dedicated application or use a dedicated user account for the integration. Each method requires specific permissions and configuration steps to ensure Security & Compliance commands can be executed successfully.\
For **detailed instructions** on how to configure each authentication method and properly set up the required parameters, refer to the **[integration documentation](https://xsoar.pan.dev/docs/reference/integrations/security-and-compliance-v2#permissions-and-authentication-setup)**.

Authentication methods configuration:
- App-only (OAuth2.0) using device code Authentication -
    1. Fill in the UPN, App ID, and Tenant ID parameters in the integration configuration.
    2. Run the ***o365-sc-auth-start*** command and follow the instructions.
    3. For testing completion of authorization process run the ***o365-sc-auth-test*** command.
- Delegated User Authentication -
    1. Fill in the 'UPN' parameter in the integration configuration. 
    2. Fill in the 'UPN Password' parameter - the user’s Microsoft 365 password (the regular sign-in password for that UPN).
    3. For testing completion of authorization process run the ***o365-sc-auth-test*** command.
    4. The following commands are only available when using the Delegated User Authentication method, as per the [Microsoft Update](https://mc.merill.net/message/MC1131771):
       - o365-sc-new-search-action
       - o365-sc-case-hold-policy-create
       - o365-sc-case-hold-policy-set
       - o365-sc-case-hold-policy-delete
       - o365-sc-case-hold-rule-create
       - o365-sc-case-hold-rule-delete 
       - o365-sc-email-security-search-and-delete-email-office-365-quick-action

**Note - If a UPN Password is provided:**  
- Even if the password is incorrect, the integration will attempt to authenticate using it.
- In this case, all connections to Microsoft Security and Compliance PowerShell will use interactive delegated authentication.


### Additional Resources
- [Entra ID App Registrations](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
- [API Permissions in Microsoft Graph](https://docs.microsoft.com/en-us/graph/permissions-reference)
- [Configure Authentication in Azure AD](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)
- [Add a Client Secret](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#option-2-create-a-new-application-secret)
