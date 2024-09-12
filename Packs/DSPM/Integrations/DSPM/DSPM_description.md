#### Integration Author: Prisma Cloud DSPM
***
#### Prisma Cloud DSPM
Remediate your data security risks. Integrate with Prisma Cloud DSPM to fetch your data security risks and remediate them with OOTB playbooks.

##### Details for Prisma Cloud DSPM workflow

Configure the instance by providing following mandatory details:
### Prisma Cloud DSPM
- Name of the instance
- Prisma Cloud DSPM server URL
- DSPM API Key

### Azure(Optional)
- Azure Storage Account name
- Azure Storage Shared Key
### GCP(Optional)
- GCP Service Account JSON

- Lifetime for slack notification ( in hours)

#### Prisma Cloud DSPM
 - To retrieve DSPM API Token, login to [Prisma Cloud DSPM Portal](https://login.dig.security/).
 - In the Prisma Cloud DSPM side menu, click **Settings**, and go to the **API** tab.
 - Enter a meaningful name and a description for the API, and click **Create Key**.
 - In the pop-up, click Copy API Key to copy the key, and click **Done**. ([more info](https://docs.dig.security/docs/create-an-api-key))

#### Azure
 - To retrieve Azure Storage Account Name & Shared Key, login to [Azure Portal](https://portal.azure.com/).
 - Navigate to the **Azure Storage Accounts**.
 - In the Storage Accounts section, you will see a list of all your storage accounts.
 - Click on the name of the storage account for which you want to retrieve the storage account name and shared key.
 - On left Panel, Click on **Access keys** under the **Security + networking** category.
 - In the Access keys page, you will find **Shared key** & **Storage account name**. ([more info](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage?tabs=azure-portal#view-account-access-keys))

#### GCP
 - To retrieve GCP Service Account JSON, login to [GCP Console](https://console.cloud.google.com/iam-admin/serviceaccounts?walkthrough_id=iam--create-service-account-keys&start_index=1&_ga=2.239242243.104752888.1725863274-893815288.1717045758#step_index=1).
 - In the GCP Console, select the project where you want to create the service account.
 - Click the email address of the service account that you want to create a key for.
 - Click the **Keys** tab.
 - Click the **Add key** drop-down menu, then select **Create new key**.
 - Select JSON as the Key type and click Create.
 - A JSON file containing the service account details will be downloaded automatically.([more info](https://cloud.google.com/iam/docs/keys-create-delete#iam-service-account-keys-create-console))


## Test Configuration

After providing the mandatory details, please test the configuration using the Test button.

---

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/dspm)