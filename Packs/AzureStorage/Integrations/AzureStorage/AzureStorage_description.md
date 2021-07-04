In order to connect to the Azure Storage Accounts and the Blob Service use either the Cortex XSOAR Azure App or the Self-Deployed Azure App.
In both options, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

1. Fill in the required parameters.
2. Run the ***!azure-storage-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!azure-storage-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (55f9764e-300a-474a-a2bb-549cece85439).

You only need to fill in your subscription ID and resource group name. For more details, follow [Azure Integrations Parameters](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#azure-integrations-params).

#### Self-Configured Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have *user_impersonation* permission and must allow public client flows (can be found under the **Authentication** section of the app).

