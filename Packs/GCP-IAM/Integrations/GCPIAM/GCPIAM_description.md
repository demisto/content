### Authentication
To configure an instance of the integration in Cortex XSOAR, you have to supply Service Account Private Key file content.

In order to create a Service Account key you have to:

### Create a Project

1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. At the top-left, click Menu menu > IAM & Admin > Create a Project.
3. In the Project Name field, enter a descriptive name for your project.
   
   Optional: To edit the Project ID, click Edit. The project ID can't be changed after the project is created, so choose an ID that meets your needs for the lifetime of the project.
4. In the Location field, click Browse to display potential locations for your project. Then, click Select
5. Click Create. The console navigates to the Dashboard page, and your project is created within a few minutes.

### Enable Google Workspace APIs

In order to use the integration capabilities, you have to enable Google Workspace APIs.
1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. At the top-left, click Navigation Menu -> APIs & Services > Library.
3. In the search field, enter the name of the API you want to enable and press Enter.
   Please enable the following APIs:
   1. Identity and Access Management (IAM) API
   2. Cloud Resource Manager API
   3. Cloud Identity API
4. In the list of search results, click the API you want to enable.
5. Click Enable.

### Create a Service Account

1. Open the [Service accounts page](https://console.developers.google.com/iam-admin/serviceaccounts).
2. If prompted, select a project, or create a new one.
3. Click add Create service account.
4. Under Service account details, type a name, ID, and description for the service account, then click Create and continue.
5. Optional: Under Grant this service account access to project, select the IAM roles to grant to the service account.
6. Click Continue.
7. Optional: Under Grant users access to this service account, add the users or groups that are allowed to use and manage the service account.
8. Click Done.
   
### Create a Service Account Key

1. Open the [Service accounts page](https://console.developers.google.com/iam-admin/serviceaccounts).
2. If prompted, select a project, or create a new one.
3. Click the email address for the service account you created.
4. Click add Create key, then click Create.
5. Click the Keys tab.
6. In the Add key drop-down list, select Create new key
7. Click Create.

Your new public/private key pair is generated and downloaded to your machine; it serves as the only copy of the private key. You are responsible for storing it securely. If you lose this key pair, you will need to generate a new one.

Please provide the downloaded file content in the integration `Service Account Private Key file content (JSON)` instance parameter.

More information about creating the required resources can be found here:
* [Create a Project](https://cloud.google.com/resource-manager/docs/creating-managing-projects)
* [Enable Google Workspace APIs ](https://developers.google.com/workspace/guides/enable-apis)
* [Create a Service Account & Service Account Key](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount)