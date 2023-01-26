To configure an instance of the integration in Cortex XSOAR, you need to supply your Storage Account Name and credentials.

Credentials are one of the following:
1. Storage Account SAS Token. 
2. Azure Managed Identities client id (relevant only if XSOAR installed on Azure VM).
   
When you configure the integration instance, enter the Storage Account name in the Storage Account field, and the credentials details in the relevant field.

#### Authentication with storage account SAS Token

To create and copy your storage account SAS Token you have to:

1. Navigate to your storage account in the Azure portal.
2. Under the Settings section please select 'Shared access signature' option.
3. In the Shared Access Signature window, make the following selections:

* Specify the signed key Start and Expiry date and time.
* Select the Time zone for the Start and Expiry date and time (default is Local).
* Define your Permissions by checking and/or clearing the appropriate check box.
  1. Allow the 'Blob' and 'File' services.
  2. Allow the 'Service', 'Container' and 'Object' resource types.
  3. Allow the following permissions: 'Read', 'Write', 'Delete', 'List', 'Create', 'Add', 'Update' and 'Immutable storage' in order to be able to achieve all integration use-cases.
  4. Allow 'Blob versioning permissions'
* Review and select "Generate".

  A new window will appear with the SAS token.
  Copy and paste the SAS token. Note it will only be displayed once and can't be retrieved once the window is closed.

  More information about Azure Storage and SAS can be found here:<br>
  [Azure Storage services](https://docs.microsoft.com/en-us/rest/api/storageservices/)

  [Grant limited access to Azure Storage resources using shared access signatures (SAS)](https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview)

  [SAS permissions overview](https://docs.microsoft.com/en-us/rest/api/storageservices/create-service-sas)

#### Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**
   2. Select your User Assigned Managed Identity -> copy the Client ID -> put it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For information about Azure Managed Identities see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)