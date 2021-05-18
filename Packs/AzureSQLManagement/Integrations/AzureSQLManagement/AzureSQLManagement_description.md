In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

To connect to the Azure SQL Management using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. Run the ***!azure-sql-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!azure-sql-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully. 

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (8f9010bb-4efe-4cfa-a197-98a2694b7e0c).

You only need to fill in your subscription ID and resource group name. You can find your resource group and subscription ID in the Azure Portal. For a detailed explanation, visit [this page](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#azure-integrations-params).
#### Self-Deployed Azure App

To use a self-configured Azure application, add a new Azure App Registration in the Azure Portal.

The application must have *user_impersonation* permission and must allow public client flows (can be found under the **Authentication** section of the app).

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
