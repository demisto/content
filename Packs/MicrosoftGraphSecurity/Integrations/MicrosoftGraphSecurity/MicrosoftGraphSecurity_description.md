# Authentication
You can authenticate either by Azure Active Directory applications or by Azure Managed Identities.

### Authentication Based on Azure Active Directory Applications

Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard compliant authentication services, which use an application to sign in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are two application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

To use the **Cortex XSOAR application** and allow Cortex XSOAR access to Microsoft Graph Security an administrator has to approve our app using an admin consent flow by clicking this **[link](https://oproxy.demisto.ninja/ms-graph-security)**.
After authorizing the Cortex XSOAR app, you will get an ID, Token, and Key which should be inserted in the integration instance settings fields.
If you previously had an API V1 configured based on the credentials obtained from this method, refer to the link above to gain new credentials with the relevant permissions.

### Important
1. The ***eDiscovery*** and ***Threat Assessment*** commands are only supported when using the `Authorization Code flow` with `Delegated (work or school account)` permission type.
2. When using `Authorization Code flow`, the connection should be tested using the ***!msg-auth-test*** command.
3. When using the `Authorization Code flow` for this integration, you should log in as an administrator or a user with administrative privileges (`Security Reader` or `Security Administrator`) after running the ***msg-generate-login-url*** command and the login window appears. For more information, see [here](https://learn.microsoft.com/en-us/graph/security-authorization).

### Authentication Based on Azure Managed Identities
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).
