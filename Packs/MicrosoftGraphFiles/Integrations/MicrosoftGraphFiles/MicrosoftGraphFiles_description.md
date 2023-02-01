# Authentication
You can authenticate either by Azure Active Directory applications or by Azure Managed Identities.
## Authentication based on Azure Active Directory applications

Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard-compliant authentication services, which use an application to sign in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are two application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

To allow access to O365 File Management (Onedrive/Sharepoint/Teams), an administrator has to approve the Cortex XSOAR app using the [admin consent flow](https://oproxy.demisto.ninja/ms-graph-files).
After authorizing the Cortex XSOAR app, you receive an ID, Token, and Key, all of which need to be entered to the corresponding fields when configuring the integration instance.


## Authentication Based on Azure Managed Identities
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-graph-files).
