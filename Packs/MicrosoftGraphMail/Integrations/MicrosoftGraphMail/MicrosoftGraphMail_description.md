# Authentication
You can authenticate either by Azure Active Directory applications or by Azure Managed Identities.
### Authentication Based on Azure Active Directory Applications

Microsoft integrations (Graph and Azure) in Cortex XSOAR use Azure Active Directory applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard compliant authentication services, which use an application to sign in or delegate authentication. For more information, see the Microsoft identity platform overview.

There are two application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

To use the Cortex XSOAR application and allow us access to O365 Outlook Mail (Using Graph API), an admin has to approve our app using an admin consent flow by clicking this [link](https://oproxy.demisto.ninja/ms-graph-mail).
After authorizing the Cortex XSOAR app, you will get an ID, Token, and Key which should be inserted in the integration instance settings fields.

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


### Using National Cloud
Using a national cloud endpoint is supported by setting the **Server URL** parameter to one of the following options:
* US Government GCC-High Endpoint: `https://graph.microsoft.us`
* US Government Department of Defence (DoD) Endpoint: `https://dod-graph.microsoft.us`
* Microsoft 365 Germany Endpoint: `https://graph.microsoft.de`
* Microsoft Operated by 21Vianet Endpoint: `https://microsoftgraph.chinacloudapi.cn`

See [Microsoft Integrations - Using National Cloud](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#using-national-cloud) for more information.


Important to know:
New commands were added to the integration, which require different application permissions:
- ***msgraph-mail-create-draft***
- ***msgraph-mail-send-draft***
- ***msgraph-mail-reply-to***
- ***send-mail***

## Lookback Parameter Notes
* Setting the lookback parameter will fetch duplicated incidents in the event that incidents that fall out during the given look-back time were already fetched.


To use these commands and to fetch incidents,
you will need to add to your application the **Mail.Send application** permission (not delegated),
and re-authorize your integration's instance.

If you do not wish to use these commands, you may keep your integration credentials the same.
