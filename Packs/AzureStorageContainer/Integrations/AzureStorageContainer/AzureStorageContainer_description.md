To configure an instance of the integration in Cortex XSOAR, you need to supply your Storage Account Name and credentials.

Credentials are one of the following:
- Storage Account SAS Token. 
- Azure Managed Identities client ID (relevant only if Cortex XSOAR is installed on Azure VM).
   
When you configure the integration instance, enter the Storage Account name in the Storage Account field, and the credentials details in the relevant field.

#### Authentication with Storage Account SAS Token

To create and copy your storage account SAS token:

1. Navigate to your storage account in the Azure portal.
2. Under the **Settings** section, select the **Shared access signature** option.
3. In the **Shared Access Signature** window, make the following selections:  
    - Specify the signed key Start and Expiry date and time.
    - Select the Time zone for the Start and Expiry date and time (default is Local).
    - Define your Permissions by checking and/or clearing the appropriate check boxes.
      - Allow the 'Blob' and 'File' services.
      - Allow the 'Service', 'Container' and 'Object' resource types.
      - Allow the 'Read', 'Write', 'Delete', 'List', 'Create', 'Add', 'Update' and 'Immutable storage' permissions to be able to implement all integration use cases.
      - Allow 'Blob versioning permissions'.
4. Review and select "Generate".    
   A new window will appear with the SAS token.  
5. Copy and paste the SAS token. Note: it will only be displayed once and can't be retrieved once the window is closed.

  For more information about Azure Storage and SAS, see:  
  - [Azure Storage services](https://docs.microsoft.com/en-us/rest/api/storageservices/)  
  - [Grant limited access to Azure Storage resources using shared access signatures (SAS)](https://docs.microsoft.com/en-us/azure/storage/common/storage-sas-overview)
  - [SAS permissions overview](https://docs.microsoft.com/en-us/rest/api/storageservices/create-service-sas)

#### Azure Managed Identities Authentication
##### Note: This option is relevant only if the integration is running on Azure VM.
Follow one of these steps for authentication based on Azure Managed Identities:

- ##### To use System Assigned Managed Identity
   - Select the **Use Azure Managed Identities** checkbox and leave the **Azure Managed Identities Client ID** field empty.

- ##### To use User Assigned Managed Identity
   1. Go to [Azure Portal](https://portal.azure.com/) -> **Managed Identities**.
   2. Select your User Assigned Managed Identity -> copy the Client ID -> paste it in the **Azure Managed Identities Client ID** field in the instance settings.
   3. Select the **Use Azure Managed Identities** checkbox.

For more information, see [Managed identities for Azure resources](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview).

#### Shared Key
##### Note: This option is relevant only if you want to block public access of a specific container.

Follow these steps to create and copy shared access keys:

1. Navigate to your storage account in the Azure portal.
2. Under the **Security + networking** section, select the **Access keys** option.
3. In the **Accesskeys** window, you will get two keys.
4. Copy any one of them and use it while configuring the instance.

- For more information, see [Shared access keys](https://learn.microsoft.com/en-gb/azure/storage/common/storage-account-keys-manage?tabs=azure-portal#regenerate-access-keys).
