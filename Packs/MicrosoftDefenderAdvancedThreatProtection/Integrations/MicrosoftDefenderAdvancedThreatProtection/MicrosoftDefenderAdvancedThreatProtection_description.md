### Deprecation Note: 
`Fetch incidents` is deprecated. Use the `Microsoft Graph Security`integration instead.

# Authentication

Microsoft integrations (Graph and Azure) in Cortex use Entra ID applications to authenticate with Microsoft APIs. These integrations use OAuth 2.0 and OpenID Connect standard-compliant authentication services, which use an Application to sign-in or delegate authentication. For more information, see the [Microsoft identity platform overview](https://learn.microsoft.com/en-us/entra/identity-platform/v2-overview).

Two application authentication methods are available:
 * [Cortex XSOAR Application](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#cortex-xsoar-application)
 * [Self-Deployed Application (via Microsoft Entra ID)](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

Depending on the authentication method that you use, the integration parameters might change.

## Cortex XSOAR App

To allow access to Microsoft Defender Advanced Threat Protection, an admin has to approve our app using an admin consent flow, by clicking on the following [link](https://oproxy.demisto.ninja/ms-defender-atp).
After authorizing the Cortex XSOAR app, you will get an *ID*, *Token*, and *Key*, which you then need to insert in the integration instance settings corresponding fields.

## Self-deployed Azure App

There are two different authentication methods for self-deployed configuration:
- [Client Credentials flow (Application Permissions)](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-webapp?view=o365-worldwide)
- [Authorization Code flow (Delegated Permissions)](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/exposed-apis-create-app-nativeapp?view=o365-worldwide)

**Note**: When using the Authorization Code flow, make sure the user you authenticate with has the required role permissions. See [this](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/initiate-autoir-investigation?view=o365-worldwide#permissions) as an example.

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add an app registration, refer to steps 1-6 under the **Self-deployed Azure Application** section of the integration documentation [here](https://xsoar.pan.dev/docs/reference/integrations/microsoft-defender-advanced-threat-protection#self-deployed-azure-application).

Select the **Use a self-deployed Azure Application** checkbox and copy the application details based on the chosen permissions type.

#### Authentication Using the Authorization Code Flow (Delegated Permissions)

- In the *ID* field, enter the application (client) ID.
- In the *Key* field, enter the client secret.
- In the *Token* field, enter the directory (tenant) ID.
- In the *Authentication Type* field, select the **Authorization Code** option.
- In the *Application Redirect URI* field, enter the application redirect URI.
- Save the instance.
- Run the `!microsoft-atp-generate-login-url` command in the War Room and follow the instructions.

#### Authentication Using the Client Credentials Flow (Application Permissions)

- In the *ID* field, enter the application (client) ID.
- In the *Key* field, enter the client secret.
- In the *Token* field, enter the directory (tenant) ID.
- In the *Authentication Type* field, select the **Client Credentials** option.
- Click **Test** to verify correct configuration.
- Save the instance.

## Azure Managed Identities

**Note**: This option is relevant only if the integration is running on Azure VM.

Follow one of these steps for authentication based on Azure Managed Identities:

#### To use System Assigned Managed Identity

- Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

#### To use User Assigned Managed Identity

- Go to [Azure Portal](https://portal.azure.com/) > **Managed Identities**.
- Select your **User Assigned Managed Identity**, copy the client ID, and paste it in the integration instance settings **Azure Managed Identities Client ID** field.
- Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
