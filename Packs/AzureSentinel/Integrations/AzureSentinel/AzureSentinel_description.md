Full documentation for this integration is available at our [reference docs](https://xsoar.pan.dev/docs/reference/integrations/azure-sentinel).

#### Self-Deployed Authentication
Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, add a new Azure App Registration in the Azure Portal. To add the registration, see the [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. In your registered app - create a new Client secret.
   1. Navigate in the Azure Portal to **App registrations** > your registered application > **Certificates & secrets** and click **+ New client secret**.
   2. Copy and save the new secret value to use in the add credentials step.
3. Assign a role to the registered app.
   1. In Azure portal, go to the Subscriptions and select the subscription you are using -> Access control (IAM).
   2. Click Add -> Add role assignment.
   3. Select the Microsoft Sentinel Contributor role -> Select your registered app, and click Save.
4. In Cortex XSOAR, go to  **Settings** > **Integrations** > **Credentials** and create a new credentials set. 
5. In the *Username* parameter, enter your registered app Application (client) ID.
6. In the *Password* parameter, enter the secret value you created.
7. Copy your tenant ID for the integration configuration usage.

#### Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).
## Configure the Server URL
If you have a dedicated server URL, enter it in the *Server Url* parameter. 

## Get the Additional Instance Parameters

To get the *Subscription ID*, *Workspace Name*, and *Resource Group* parameters, in the Azure Portal navigate to **Azure Sentinel** > your workspace > **Settings** and click the **Workspace Settings** tab.

## Lookback Parameter Notes
* In case the **look-back** parameter is initialized with a certain value and during a time that incidents were fetched, if changing the look-back to a number that is greater than the previous value, then in the initial incident fetching there will be incident duplications. If the integration was already set with look-back > 0, and the look-back is not being increased at any point of time, then those incident duplications would not occur.
* Using a look-back value that is very large can lead to an increase in the memory usage of the system and additional API calls. It is recommended to use a small value (e.g., 1-5 minutes).