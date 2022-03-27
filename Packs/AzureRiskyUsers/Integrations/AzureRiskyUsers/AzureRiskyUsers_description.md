## Configure Azure Risky Users on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AzureRiskyUsers.
3. Click **Add instance** to create and configure a new integration instance.

## Authorization
In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to Microsoft Risky User using either Cortex XSOAR Graph App or the Self-Deployed Graph App:
1. Fill in the required parameters.
2. Run the ***!msgraph-identity-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!msgraph-identity-auth-complete*** command.

#### Cortex XSOAR Graph App

In order to use the Cortex XSOAR Azure application, use the application ID (ec854987-95fa-4c8f-8056-768dd0f409ac).

#### Self-Deployed Graph App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with mobile and desktop flows enabled.

#### Required Permissions
*Make sure to provide the following permissions for the app to work with Azure Risky Users:*
 - ***IdentityRiskyUser.Read.All*** - https://docs.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0
 - ***IdentityRiskEvent.Read.All*** - https://docs.microsoft.com/en-us/graph/api/riskdetection-get?view=graph-rest-1.0
 
## Retrieve Client ID (Application ID)

1. In **Azure Portal** navigate to **App Registrations** and find the relevant application.
2. In the **Overview** tab, copy the value **Application (client) ID**.
3. Insert the value to **Client ID** in the Azure Risky Users instance configuraton.
