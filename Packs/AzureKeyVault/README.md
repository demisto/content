Azure Key Vault is a cloud service for securely storing and accessing secrets. A secret is anything that you want to tightly control access to, such as passwords, certificates, or cryptographic keys. 

## What does this pack do?
- Create or update a key vault in a specified subscription.
- Get or delete a specified key vault.
- Get information about the vaults associated with a specified subscription.
- Update access policies in a key vault in a specified subscription.
- Get the public part of a stored key.
- List the keys in a specified vault.
- Delete a key of any type from storage in the Azure key vault.
- Get or delete a specified secret from a specified key vault.
- List the secrets in a specified key vault.
- Get information about a specific certificate.
- List certificates in a specified key vault.
- Get the policy of the specified certificate.

 To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the [Azure app registration article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app)
 You need to grant the following permissions for the app registration:
   - Azure Service Management - permission user_impersonation of type Delegated
   - Azure Key Vault - permission user_impersonation of type Delegated.

You will need to get the following information from the Azure portal:
- Client ID and tenant ID values 
- Client secret value
- Subscription ID and the resource group values

You will also need to fetch credentials from the Azure key vault. The credentials will be in the following format: KEY_VAULT_NAME/SECRET_NAME
