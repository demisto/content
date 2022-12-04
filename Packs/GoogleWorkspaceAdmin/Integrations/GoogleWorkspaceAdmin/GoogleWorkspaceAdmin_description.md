# Configure an API account on Google Workspace Admin
Configure a Service Account and retrieve its key in JSON format by following the steps mentioned here: [https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount) or in the integration README.

In order to retrieve the Customer ID, do the following:
1. In the Admin console, go to Menu => Account => Account settings => Profile.
2. Under Customer ID, you will find your organization's unique ID.

To execute the commands with the help of the service account, perform the following steps:
1. You must be signed in as a super administrator for this task.
2. Open your Google Admin console (at https://admin.google.com).
3. Go to Admin roles.
4. Click the role you want to assign (the role must have the appropriate privileges (listed below) in order to execute the commands).
5. Click on Assign Admin.
6. On the opened page, click Assign Service Accounts.
7. Append the email of the Service Account created and click ASSIGN ROLE to save.

#### The necessary privileges
##### Mobile devices:
1. Admin console privileges => Services => Mobile Device Management => Manage Devices and Settings.

##### ChromeOs devices:
1. Admin console privileges => Services => Chrome Management => Settings => Manage Chrome OS Devices => Read.
2. Admin console privileges => Services => Chrome Management => Settings => Manage Chrome OS Device Settings.