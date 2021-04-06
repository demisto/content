## Authorization
In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to Microsoft Graph Identity & Access using either Cortex XSOAR Graph App or the Self-Deployed Graph App:
1. Fill in the required parameters.
2. Run the ***!msgraph-identity-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!msgraph-identity-auth-complete*** command.

At the end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Graph App

In order to use the Cortex XSOAR Azure application, use the default application ID (597c0375-766f-4e6d-ad2a-f48117044ac5).

#### Self-Deployed Graph App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with mobile and desktop flows enabled.

#### Required Permissions
* RoleManagement.ReadWrite.Directory - Application
