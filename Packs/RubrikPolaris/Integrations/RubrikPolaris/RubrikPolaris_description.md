Support and maintenance for this integration are provided by the author. 
Please use the following contact details:
- "Email": [support@rubrik.com](mailto:support@rubrik.com)
- "URL": [https://www.rubrik.com/support/](https://www.rubrik.com/support/)

Steps to get "Service Account JSON".
- Log in to the Polaris web UI.
- Go to "Settings" and select "User Management". Select Users tab.
- Click "Service Accounts" and then click "Add Service Account".
- Enter a "Name" for the service account.
- Click "Next".
- The Roles page appears with a list of available roles. Select the roles to be assigned to the service account.
- Click "Add".
- Click "Download As JSON" to download a file containing the client credentials, and the access token URI in JSON format.
- The client can use this service account JSON in order to authenticate themselves and invoke Polaris API endpoints.