In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to the Azure Network Security Group using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. Run the ***!azure-nsg-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!azure-nsg-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully. 

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (d4736600-e3d5-4c97-8e65-57abd2b979fe).

You only need to fill in your subscription ID and resource group name. 

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have *user_impersonation* permission and must allow public client flows (can be found under the **Authentication** section of the app).
