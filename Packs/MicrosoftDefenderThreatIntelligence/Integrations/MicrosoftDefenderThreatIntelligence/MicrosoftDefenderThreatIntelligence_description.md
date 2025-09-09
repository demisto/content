**This integration requires Defender Threat Intelligence—premium version**

## Authorization
To use Microsoft Graph Services, you need to configure authentication. There are three authentication methods available:
- Client Credentials Flow (Recommended)
- Device Code Flow
- Azure Managed Identities

### Device Code Flow
___
In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

To connect to Microsoft Defender Threat Intelligence using either Cortex XSOAR Azure app or the Self-Deployed Azure app:
1. Fill in the required parameters.
2. Run the ***!msg-defender-threat-intel-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!msg-defender-threat-intel-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

To use the Cortex XSOAR Azure application, use the default application ID (7f55ea8c-2e5c-4a52-aafa-d0bfc632b242).  
A detailed explanation on how to register an app can be found [here](https://docs.microsoft.com/en-us/power-apps/developer/data-platform/walkthrough-register-app-azure-active-directory).

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App registration in the Azure portal, with mobile and desktop flows enabled.

### Client Credentials Flow

1. Enter your Client/Application ID in the ***Application ID*** parameter.
2. Enter your Client Secret in the ***Client Secret*** parameter.
3. Enter your Tenant ID in the ***Tenant ID*** parameter.

### Azure Managed Identities Authentication

**Note**: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).
