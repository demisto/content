## Authorization
In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to Microsoft Teams Management using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. Run the ***!microsoft-teams-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!microsoft-teams-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (3307a0ab-612c-47af-b3b5-8208247562db).

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with mobile and desktop flows enabled.

Required Permissions
* Group.ReadWrite.All - Application
* Team.ReadBasic.All - Application
* TeamMember.ReadWrite.All - Application
