### Authorize Cortex XSOAR for Azure Data Explorer (self-deployed configuration)

Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).
2. Make sure the following permissions are granted for the app registration:
   - Azure Data Explorer - permission `user_impersonation` of type `Delegated`
3. Enter your client ID in the ***Apllication ID*** parameter. 

### Get the additional instance parameters

To get the ***Cluster URL*** parameter navigate in the Azure Portal to ***Azure Data Explorer Clusters*** > YOUR-CLUSTER and copy ***URI*** tab.
