### Deprecation Note: 
`Fetch incidents` is deprecated. Use the `Microsoft Graph Security`integration instead.

# Authentication

Two application authentication methods are available:
 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application (via Microsoft Entra ID)](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

**Note**: When using the Authentication Code flow (either via the Cortex XSOAR application or by choosing delegated permissions for a self-deployed app), ensure the authenticated user has the required role permissions.

Depending on the authentication method that you use, the integration parameters might change.

## Cortex XSOAR App

This integration can use OAuth 2.0 and OpenID Connect standard-compliant authentication services to sign-in or delegate authentication. For more information, see the Microsoft identity platform overview.

To allow access to Microsoft Defender Advanced Threat Protection, an admin has to approve our app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-defender-atp).
After authorizing the Cortex XSOAR app, you will get an ID, Token, and Key, which should be inserted in the integration instance configuration's corresponding fields.

## Self-deployed Azure App

There are two different authentication methods for self-deployed configuration:
- [Client Credentials flow (Application Permissions)](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-webapp?view=o365-worldwide)
- [Authorization Code flow (Delegated Permissions)](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-nativeapp?view=o365-worldwide)

**Note**: When using the Authorization Code Flow, make sure the user you authenticate with has the required role permissions. See [this](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/initiate-autoir-investigation?view=o365-worldwide#permissions) as an example.

To use a self-configured Azure application:

- Add a App Registration in Microsoft Entra ID with the required permissions, as described in steps 1-7 under the **Self-deployed Azure Application** section of the integration documentation [here](https://xsoar.pan.dev/docs/reference/integrations/microsoft-defender-advanced-threat-protection#self-deployed-azure-application).

- Select the **Use a self-deployed Azure Application** checkbox and copy the application details based on the chosen permissions type:
  - ##### To use Delegated Permissions
    - In the **ID** field, enter the Application (client) ID.
    - In the **Key** field, enter the Client secret.
    - In the **Token** field, enter the Directory (tenant) ID.
    - In the **Authentication Type** field, select "Authorization Code".
    - In the **Application Redirect URI** field, enter the Application redirect URI.
    - Click **Save & Exit**.
    - Run the **microsoft-atp-generate-login-url** command and follow the instructions.

  - ##### To use Application Permissions
    - In the **ID** field, enter the Application (client) ID.
    - In the **Key** field, enter the Client secret.
    - In the **Token** field, enter the Directory (tenant) ID.
    - In the **Authentication Type** field, select "Client Credentials".
    - Click **Test** to verify correct configuration.
    - Click **Save & Exit**.

## Azure Managed Identities
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) > **Managed Identities**.
   2. Select your User Assigned Managed Identity > copy the Client ID > paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
