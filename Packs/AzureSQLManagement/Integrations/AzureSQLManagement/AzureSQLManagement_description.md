In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to the Azure Network Security Group using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. Run the ***!azure-sql-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!azure-sql-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully. 

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (b911e858-56ff-4a4b-b029-6ee67675e2cb).

You only need to fill in your subscription ID and resource group name. You can find your resource group and subscription ID at Azure Portal.

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have *user_impersonation* permission and must allow public client flows (can be found under the **Authentication** section of the app).
