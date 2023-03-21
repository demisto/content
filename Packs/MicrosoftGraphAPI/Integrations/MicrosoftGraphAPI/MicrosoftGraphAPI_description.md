To use this integration, you need to configure authentication. There are three authentication methods available:  
- Cortex XSOAR Azure app 
- Self-Deployed Azure app  
- Azure Managed Identities Authentication

Note: Depending on the authentication method that you use, the integration parameters might change.

#### Cortex XSOAR Azure App

In this method, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

To configure the integration:

1. The **Application ID** integration parameter should be set to `8922dd2d-7539-4711-b839-374f86083959` (the Cortex XSOAR Azure app ID).

2. The **Scope** integration parameter should be set according to the requested OAuth2 permissions types to grant access to in Microsoft identity platform, for more details see the [Microsoft documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent).

3. The **Application Secret** and the **Tenant ID** integration parameters should be left blank.

4. Run the ***msgraph-api-auth-start*** command - you will be prompted to open the page https://microsoft.com/devicelogin and enter the generated code.

5. Run the ***msgraph-api-auth-complete*** command.

6. Run the ***msgraph-api-test*** command to ensure connectivity to Microsoft. 
 
#### Self-Deployed Azure App

For more information, see this [article](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application). 

The **Application Secret** and the **Tenant ID** integration parameters are required for this method.

Run the **msgraph-api-test** command to ensure connectivity to Microsoft.

The integration supports only Application permission type, and does not support Delegated permission type. 

#### Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
