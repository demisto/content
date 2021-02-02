## Authorization
In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to the Azure Network Security Group using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. Run the ***!msgraph-apps-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!msgraph-apps-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (3307a0ab-612c-47af-b3b5-8208247562db).

You only need to fill in your subscription ID and resource group name. For more details, follow [Azure Integrations Parameters](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#azure-integrations-params).

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with mobile and desktop flows enabled.

Required Permissions
* Application.ReadWrite.All - Application
