### Authentication
To configure an instance of the integration in Cortex XSOAR, you have to supply Service Account Private Key file content.

In order to use the integration, in the first stage, you have to create a project.
Information about how to create project can be found [here](https://cloud.google.com/resource-manager/docs/creating-managing-projects)

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

### Grant Permissions

You have to grant the required permissions to the created Service Account in order to use in the integration command.<br>
List of the required permissions for every command can be find below.<br>
You can grant the permissions by per-defined roles or by creating a custom role. 

#### Create a Custom Role

1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Click the navigation menu and select IAM & Admin then Roles.
3. Click + Create Role on the top toolbar.
4. Add a Title, Description, ID and ensure the role is marked for General Availability.
5. Add the required permissions by clicking + ADD PERMISSIONS.
6. Click CREATE.

#### Grant Role Access to Service Account

1. Open the [Google Cloud Console](https://console.cloud.google.com/).
2. Select IAM & Admin > IAM.
3. Click the down arrow in the top menu bar for the project.
4. From the Select from drop-down, select an organization that contains the GCP project(s) that you want the integration to monitor.
5. Select ALL tab. Then select the required organization.
6. Click Add. Note that you must have permission to add members to the organization or project for the ADD button to be active.
7. Add a member and roles to a project or organization. In the New members field, paste the email address of the created service account.
8. From the Select a role drop-down, and select the required roles.
9. Click Save.

### Command Required Permissions

|Command Name|Permissions|
|---|---|
| gcp-iam-projects-get | resourcemanager.projects.get |
| gcp-iam-project-iam-policy-get | resourcemanager.projects.getIamPolicy |
| gcp-iam-project-iam-permission-test | There are no permissions required for making this API call. |
| gcp-iam-project-iam-member-add | resourcemanager.projects.getIamPolicy <br> resourcemanager.projects.setIamPolicy |
| gcp-iam-project-iam-member-remove | resourcemanager.projects.getIamPolicy <br> resourcemanager.projects.setIamPolicy |
| gcp-iam-project-iam-policy-set | resourcemanager.projects.getIamPolicy <br> resourcemanager.projects.setIamPolicy |
| gcp-iam-project-iam-policy-create | resourcemanager.projects.getIamPolicy <br> resourcemanager.projects.setIamPolicy |
| gcp-iam-project-iam-policy-remove | resourcemanager.projects.getIamPolicy <br> resourcemanager.projects.setIamPolicy |
| gcp-iam-folders-get | resourcemanager.folders.list <br> resourcemanager.folders.get |
| gcp-iam-folder-iam-policy-get | resourcemanager.folders.getIamPolicy |
| gcp-iam-folder-iam-permission-test | There are no permissions required for making this API call. |
| gcp-iam-folder-iam-member-add | resourcemanager.folders.getIamPolicy <br> resourcemanager.folders.setIamPolicy |
| gcp-iam-folder-iam-member-remove | resourcemanager.folders.getIamPolicy <br> resourcemanager.folders.setIamPolicy |
| gcp-iam-folder-iam-policy-set | resourcemanager.folders.getIamPolicy <br> resourcemanager.folders.setIamPolicy |
| gcp-iam-folder-iam-policy-create | resourcemanager.folders.getIamPolicy <br> resourcemanager.folders.setIamPolicy |
| gcp-iam-folder-iam-policy-remove | resourcemanager.folders.getIamPolicy <br> resourcemanager.folders.setIamPolicy |
| gcp-iam-organizations-get | resourcemanager.organizations.get |
| gcp-iam-organization-iam-policy-get | resourcemanager.organizations.getIamPolicy |
| gcp-iam-organization-iam-permission-test | There are no permissions required for making this API call. |
| gcp-iam-organization-iam-member-add | resourcemanager.organizations.getIamPolicy <br> resourcemanager.organizations.setIamPolicy  |
| gcp-iam-organization-iam-member-remove | resourcemanager.organizations.getIamPolicy <br> resourcemanager.organizations.setIamPolicy |
| gcp-iam-organization-iam-policy-set | resourcemanager.organizations.setIamPolicy |
| gcp-iam-organization-iam-policy-create | resourcemanager.organizations.getIamPolicy <br> resourcemanager.organizations.setIamPolicy |
| gcp-iam-organization-iam-policy-remove | resourcemanager.organizations.getIamPolicy <br> resourcemanager.organizations.setIamPolicy |
| gcp-iam-group-create | resourcemanager.organizations.get |
| gcp-iam-group-list | resourcemanager.organizations.get |
| gcp-iam-group-get | resourcemanager.organizations.get |
| gcp-iam-group-delete | resourcemanager.organizations.get |
| gcp-iam-group-membership-create | resourcemanager.organizations.get |
| gcp-iam-group-membership-list | resourcemanager.organizations.get |
| gcp-iam-group-membership-get | resourcemanager.organizations.get |
| gcp-iam-group-membership-role-add | resourcemanager.organizations.get |
| gcp-iam-group-membership-role-remove | resourcemanager.organizations.get |
| gcp-iam-group-membership-delete | resourcemanager.organizations.get |
| gcp-iam-service-account-create | iam.serviceAccounts.create |
| gcp-iam-service-account-update | iam.serviceAccounts.update |
| gcp-iam-service-accounts-get | iam.serviceAccounts.get |
| gcp-iam-service-account-enable | iam.serviceAccounts.enable |
| gcp-iam-service-account-disable |iam.serviceAccounts.disable  |
| gcp-iam-service-account-delete | iam.serviceAccounts.delete |
| gcp-iam-service-account-key-create | iam.serviceAccountKeys.create |
| gcp-iam-service-account-keys-get | iam.serviceAccountKeys.get <br> iam.serviceAccountKeys.list |
| gcp-iam-service-account-key-enable | Required grant 'Service Account Key Admin' role permission |
| gcp-iam-service-account-key-disable | Required grant 'Service Account Key Admin' role permission |
| gcp-iam-service-account-key-delete | iam.serviceAccountKeys.delete |
| gcp-iam-organization-role-create | iam.roles.create |
| gcp-iam-organization-role-update | iam.roles.update |
| gcp-iam-organization-role-permission-add | iam.roles.get iam.roles.update |
| gcp-iam-organization-role-permission-remove | iam.roles.get iam.roles.update |
| gcp-iam-organization-role-list | iam.roles.list |
| gcp-iam-organization-role-get | resourcemanager.organizations.get |
| gcp-iam-organization-role-delete | iam.roles.delete |
| gcp-iam-project-role-create | iam.roles.create |
| gcp-iam-project-role-update | iam.roles.update |
| gcp-iam-project-role-permission-add | iam.roles.get <br> iam.roles.update |
| gcp-iam-project-role-permission-remove | iam.roles.get <br> iam.roles.update |
| gcp-iam-project-role-list | iam.roles.list |
| gcp-iam-project-role-get | iam.roles.get |
| gcp-iam-project-role-delete | iam.roles.delete |
| gcp-iam-testable-permission-list | There are no permissions required for making this API call. |
| gcp-iam-grantable-role-list | iam.roles.list <br> resourcemanager.organizations.getIamPolicy <br> resourcemanager.projects.getIamPolicy <br> resourcemanager.folders.getIamPolicy |
| gcp-iam-role-get | iam.roles.get |
| gcp-iam-role-list | iam.roles.list |




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