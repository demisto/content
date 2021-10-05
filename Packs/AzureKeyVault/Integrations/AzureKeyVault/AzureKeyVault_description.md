 ### Authorize Cortex XSOAR for Azure Key Vault (self-deployed configuration)
Follow these steps for a self-deployed configuration.


1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Azure app registration article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)


2. You must grant to YOUR-REGISTERED-APP permissions, for your Azure Key vault. 


3. To get the client id and the tenant id, navigate in the Azure Portal to App registrations > YOUR-REGISTERED-APP > click on "overview".
   

4. To get the client secret,in YOUR-REGISTERED-APP click on "Certificates & secrets" > and go to "Client secrets". 


5. To get the Subscription ID and the Resource Group parameters, navigate in the Azure Portal to Resource groups > YOUR-RESOURCE-GROUP-NAME > click on overview.


6. Enter your client ID in the Client ID parameter.


7. Enter your client secret in the Client Secret parameter.


8. Enter your tenant ID in the Tenant ID parameter.


9. Enter your subscription ID in the Subscription ID parameter.


10. Enter your resource group name in the Resource Group Name parameter.

 ### Fetch credentials from Azure Key Vault
In order to fetch credentials to the Cortex XSOAR credentials store,you should follow the next steps:
1. Check Fetches credentials parameter.
2. Fill Key Vault names to fetch secrets from.
3. Fill secret names to fetch.

After the Azure Key Vault integration instance is created, the credentials will be fetched
to the Cortex XSOAR credentials store in the following format:

Credential Name: KEY_VAULT_NAME/SECRET_NAME

Username: SECRET_NAME

Password: SECRET_VALUE