To use this integration, you need to configure authentication. There are three authentication methods available:  
- Cortex XSOAR Azure app 
- Self-Deployed Azure app  
- Azure Managed Identities Authentication

Note: Depending on the authentication method that you use, the integration parameters might change.

#### Cortex XSOAR Azure App
You need to grant Cortex XSOAR authorization to access Azure Active Directory Users.

1. Access the [authorization flow](https://oproxy.demisto.ninja/ms-graph-user).
2. Click the **Start Authorization Process** button and you will be prompted to grant Cortex XSOAR permissions for your Azure Active Directory Users.
3. Click the **Accept** button and you will receive your ID, token, and key. You will need to enter these when you configure the Azure Active Directory Users integration instance in Cortex XSOAR.

#### Self-Deployed Azure App

There are two different authentication methods for self-deployed configuration: 
- [Client Credentials flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#client-credentials-flow)
- [Authorization Code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authorization-code-flow)

We recommend using the Client Credentials flow.

In order to use the ***msgraph-user-change-password*** command, you must use with the Authorization Code flow.

**Note:** When using the Authorization Code flow, make sure the user you authenticate with has the relevant roles in Azure AD in order to execute the operation.



#### Azure Managed Identities Authentication
___
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).