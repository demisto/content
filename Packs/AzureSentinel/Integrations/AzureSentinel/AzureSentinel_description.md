Full documentation for this integration is available at our [reference docs](https://xsoar.pan.dev/docs/reference/integrations/azure-sentinel).


## Authorize Cortex XSOAR for Azure Sentinel

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. In your registered app - create a new Client secret.
   1. Navigate in the Azure Portal to **App registrations** > your registered application > **Certificates & secrets** and click **+ New client secret**.
   2. Copy and save the new secret value to use in the add credentials step.
3. Assign a role to the registered app.
   1. In Azure portal go to the Subscriptions and select the subscription you are using -> click Access control (IAM).
   2. Click Add -> click Add role assignment.
   3. Select the Azure Sentinel Contributor role -> Select your registered app -> click Save.
4. In Cortex XSOAR, go to  **Settings** > **Integrations** > **Credentials** and create a new credentials set. 
5. Enter your registered app Application (client) ID in the ***Username*** parameter.
6. Enter the secret value you created in the *Password* parameter.
7. Copy your tenant ID for the integration configuration usage.

## Configure the server URL
If you have a dedicated server URL, enter it in the *Server Url* parameter. 

## Get the additional instance parameters

To get the *Subscription ID*, *Workspace Name* and *Resource Group* parameters, in the Azure Portal navigate  to **Azure Sentinel** > your workspace > **Settings** and click the **Workspace Settings** tab.
