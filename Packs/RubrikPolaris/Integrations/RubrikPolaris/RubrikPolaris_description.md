Steps to get "Service Account JSON".
- Log in to the Rubrik Security Cloud web UI.
- Go to "Settings" and select "User Management". Select Users tab.
- Click "Service Accounts" and then click "Add Service Account".
- Enter a "Name" for the service account.
- Click "Next".
- The Roles page appears with a list of available roles. Select the roles to be assigned to the service account.
- Click "Add".
- Click "Download As JSON" to download a file containing the client credentials, and the access token URI in JSON format.
- The client can use this service account JSON in order to authenticate themselves and invoke RSC API endpoints.