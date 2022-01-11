#### Note: This integration supports self-deployed configuration only.
### Authorize Cortex XSOAR for Azure Key Vault (self-deployed configuration)
#### Follow these steps for a self-deployed configuration.

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Azure app registration article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)


2. Make sure the following permissions are granted for the app registration:
   Azure Service Management - permission user_impersonation of type Delegated,
   Azure Key Vault - permission user_impersonation of type Delegated.


#### Get client ID and tenant ID values 

1. In the Azure portal, select Azure Active Directory.
2. From App registrations in Azure AD, select your application.
3. Copy the Directory (tenant) ID and enter it in the Tenant ID parameter.
4. Copy the Application ID and store it in the Client ID parameter.
   
#### Get client secret value

1. In the Azure portal, select Azure Active Directory.
2. From App registrations in Azure AD, select your application.
3. Select Certificates & secrets.
4. Select Client secrets -> New client secret.
5. Provide a description of the secret, and a duration. When done, select Add.
6. After saving the client secret, the value of the client secret is displayed. 
7. Copy this value and enter it in the Client Secret parameter.

#### Get Subscription ID and the Resource Group values

1. In the Azure portal, select Resource groups.
2. Select your resource group name.
3. Copy the Subscription ID and enter it in the Subscription ID parameter.
4. Copy your resource group name and enter it in the Resource Group Name parameter.


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