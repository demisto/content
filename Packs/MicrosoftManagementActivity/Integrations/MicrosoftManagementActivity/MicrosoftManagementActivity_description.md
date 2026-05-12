Microsoft Management Activity API (O365/Azure Events) should be used to retrieve content records from the various Microsoft Management Activity content types.
Through the integration you can subscribe to new content types or stop your subscription, list the available content of each content type, and most importantly - fetch new content records from content types of your choice as Cortex XSOAR incidents.

# Authentication
You can authenticate either by Azure Active Directory applications or by Azure Managed Identities.

## Authentication based on Azure Active Directory applications

There are two application authentication methods available:

 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

To use the **Cortex XSOAR application** and allow Cortex XSOAR access to Microsoft Management Activity API, you will be required to approve our app using an admin consent flow by clicking this **[link](https://oproxy.demisto.ninja/ms-management-api)**.
After authorizing the Cortex XSOAR app, you will get an ID, Token, and Key which should be inserted in the integration instance settings fields.

**Note**: These credentials are valid for a single instance only.


### Self-Deployed Configuration
1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Make sure the following permissions are granted for the app registration:
    - `User.Read ` of type `Delegated`
    - `ActivityFeed.Read` of type `Delegated`
    - `ActivityFeed.Read` of type `Application`
    - `ActivityFeed.ReadDlp` of type `Delegated`
    - `ActivityFeed.ReadDlp` of type `Application`
    - `ServiceHealth.Read` of type `Delegated`
    - `ServiceHealth.Read` of type `Application`
3. Enter your client ID in the ***ID*** parameter field. 
4. Enter your client secret in the ***Key*** parameter field.
5. Enter your tenant ID in the ***Token*** parameter field.
6. Enter your redirect URI in the ***Redirect URI*** parameter field.
7. Save the instance.
8. Run the `!ms-management-activity-generate-login-url` command in the War Room and follow the instruction.

### Authentication using Azure Managed Identities 
___
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).

