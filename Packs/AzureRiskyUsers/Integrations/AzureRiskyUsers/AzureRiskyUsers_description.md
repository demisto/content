## Configure Azure Risky Users on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AzureRiskyUsers.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    |Client ID|True|
    |Use system proxy|False|
    |Trust any certificate|False|

---

To connect to the Azure Risky Users platform using either the Cortex XSOAR Azure application or the Self-Deployed Azure application:
1. Fill in the required parameters.
   Make sure to provide the following permissions for the app to work with Azure Risky Users:
   - IdentityRiskyUser.Read.All - https://docs.microsoft.com/en-us/graph/api/riskyuser-list?view=graph-rest-1.0
   - IdentityRiskEvent.Read.All - https://docs.microsoft.com/en-us/graph/api/riskdetection-get?view=graph-rest-1.0
2. Run the !azure-risky-users-auth-start command. Follow the instructions that appear.
3. Run the !azure-risky-users-auth-complete command.

At the end of the process, a confirmation message appears.


## Retrieve Client ID (Application ID)

1. In **Azure Portal** navigate to **App Registrations** and find the relevant application.
2. In the **Overview** tab, copy the value **Application (client) ID**.
3. Insert the value to **Client ID** in the Azure Risky Users instance configuraton.
