In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to the Azure Data Explorer using either Cortex XSOAR Azure App or the Self-Deployed Azure App:

1. Fill in the required parameters.
2. Run the ***!azure-data-explorer-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!azure-data-explorer-auth-complete*** command.

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
