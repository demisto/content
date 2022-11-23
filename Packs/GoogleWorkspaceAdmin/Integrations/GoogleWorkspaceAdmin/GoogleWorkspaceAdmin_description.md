# Configure an API account on Google Workspace Admin
Configure a Service Account and retrieve its key in JSON format by following the steps mentioned here: [https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount](https://developers.google.com/identity/protocols/oauth2/service-account#creatinganaccount) or in the integration README.

### Commands and its scopes
* google-mobiledevice-action
	* https://www.googleapis.com/auth/admin.directory.device.mobile.action  
* google-mobiledevice-list
	* https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
* google-chromeosdevice-action
	* https://www.googleapis.com/auth/admin.directory.device.chromeos
* google_chromeosdevice_listt 
	* https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly

To execute the commands with the help of the service account, perform the following steps:
1. You must be signed in as a super administrator for this task.
2. Open your Google Admin console (at https://admin.google.com).
3. Go to Admin roles.
4. Click the role you want to assign (the role must have the appropriate privileges in order to execute the commands).
5. Click on Assign Admin.
6. On the opened page, click Assign Service Accounts.
7. Append the email of the Service Account created and click ASSIGN ROLE to save.