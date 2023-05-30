
## Authorize Cortex XSOAR for Azure Active Directory Users (Cortex XSOAR Azure App)

You need to grant Cortex XSOAR authorization to access Azure Active Directory Users.

1. Access the [authorization flow](https://oproxy.demisto.ninja/ms-graph-user).
2. Click the **Start Authorization Process** button and you will be prompted to grant Cortex XSOAR permissions for your Azure Active Directory Users.
3. Click the **Accept** button and you will receive your ID, token, and key. You will need to enter these when you configure the Azure Active Directory Users integration instance in Cortex XSOAR.

## Authorize Cortex XSOAR for Azure Active Directory Users (Self deployed Azure App)

There are two different authentication methods for self-deployed configuration: 
- [Client Credentials flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)
- [Authorization Code flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow)

We recommend using the Client Credentials flow.

In order to use the ***msgraph-user-change-password*** command, you must use with the Authorization Code flow.

**Note:** When using the Authorization Code flow, make sure the user you authenticate with has the relevant roles in Azure AD in order to execute the operation.

### Self-Deployed configuration
- [Client Credentials flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)
- [Authorization Code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#authorize-on-behalf-of-a-user)


## Azure Managed Identities Authentication
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