In order to connect to the Azure Data Explorer using either Cortex XSOAR Azure App or the Self-Deployed Azure App, use one of the following methods:

1. *Authorization Code Flow* (Recommended).
2. *Device Code Flow*.

### Authentication Using the Authorization Code Flow (recommended)

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. In the **Authentication Type** field, select the **Authorization Code** option.
3. In the **Application ID** field, enter your Client/Application ID. 
4. In the **Client Secret** field, enter your Client Secret.
5. In the **Tenant ID** field, enter your Tenant ID .
6. In the **Application redirect URI** field, enter your Application redirect URI.
7. Save the instance.
8. Run the `!azure-data-explorer-generate-login-url` command in the War Room and follow the instruction.
9. Save the instance.
   
### Authentication Using the Device Code Flow

Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Azure Data Explorer with Cortex XSOAR.

1. Fill in the required parameters.
2. In the **Authentication Type** field, select the **Device Code** option.
3. Run the ***!azure-data-explorer-auth-start*** command.
4. Follow the instructions that appear.
5. Run the ***!azure-data-explorer-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

### Cortex XSOAR Azure App
In order to use the Cortex XSOAR Azure application, use the default application ID (a9ce8db2-847a-46af-9bfb-725d8a8d3c53).

### Self-Deployed Azure App

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Make sure the following permissions are granted for the app registration:
   - Azure Data Explorer - permission `user_impersonation` of type `Delegated`
3. Enter your client ID in the ***Apllication ID*** parameter. 

### Get the additional instance parameters

To get the ***Cluster URL*** parameter navigate in the Azure Portal to ***Azure Data Explorer Clusters*** > YOUR-CLUSTER and copy ***URI*** tab.
