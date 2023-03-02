
### Authorize Cortex XSOAR for Azure Key Vault 

#### Self-Deployed Authentication
Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, add a new Azure App Registration in the Azure Portal. To add the registration, see the [Azure app registration article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).


2. Make sure the following permissions are granted for the app registration:  
   - Azure Service Management - permission user_impersonation of type Delegated
   - Azure Key Vault - permission user_impersonation of type Delegated


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

#### Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to the [Azure Portal](https://portal.azure.com/) -> **Managed Identities**
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).


### Get Subscription ID and the Resource Group values

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
