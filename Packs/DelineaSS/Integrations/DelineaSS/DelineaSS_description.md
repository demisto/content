Delinea Secret Server and Platform is the fully featured Privileged Account Management (PAM) solution available both on premise and in the cloud. It empowers security and IT ops teams to secure and manage all types of privileged accounts and offers the fastest time to value of any PAM solution. This integration was integrated and tested with version 6.0 of Delinea.

To use this integration, you must have an account on your Delinea Secret Server or Platform.

As required parameters, you must specify:

**Server URL** - URL Delinea Secret Server or Platform, for example https://example.com

Credentials for logging into Delinea Secret Server or Platform.

**Username** - username to authenticate to Secret or Platform

**Password** - password to authenticate to Secret Server or Platform

You can pre-add them to the Credential or usage input Username and Password.

Use check box **Trust any certificate (not secure)** for insecure connections.

Use check box **Use system proxy settings** for proxy.

If you want to use the function of synchronizing secrets stored in Delinea Secret Server or Platform, check the box **Fetches Credentials** and fill in the field with a list of the secret id(s) of the secrets separated by commas.

You can find the more detail about Fetches Credentials and sync credentials from below link:
https://docs.delinea.com/online-help/products/integrations/current/pan/xsoar-secret-server

Use the **TEST** button to check if the parameters for integration are correct. In case of successful authentication on the Delinea Secret Server or Platform and correct filling of all other parameters, you will receive a response **Success**.

This integration performs some REST API transfers to the Delinea Secret Server or Platform, the full description of which is given in the server documentation.

The following commands are implemented:

- delinea-folder-create Create a new Secret folder

- delinea-folder-delete Delete a folder by folder ID

- delinea-folder-search Search folder by folder name

- delinea-folder-update Update a single secret folder by ID

- delinea-secret-checkin Check In a secret

- delinea-secret-checkout Check Out a Secret

- delinea-secret-create Create a new Secret

- delinea-secret-delete Delete secret

- delinea-secret-get Get secret object by ID secret

- delinea-secret-password-get Retrieved password from secret

- delinea-secret-password-update Update password for a secret by ID

- delinea-secret-rpc-changepassword Change a secret's password

- delinea-secret-search Search secret ID by multiply parameters

- delinea-secret-search-name Search ID secret by Name

- delinea-secret-username-get Retrieved username from secret

- delinea-secret-server-user-create Create a new user in Secret Server

- delinea-secret-server-user-delete Delete user by ID from Secret Server

- delinea-secret-server-user-search Search, filter, sort, and page users in Secret Server

- delinea-secret-server-user-update Update a single user by ID in Secret Server

- delinea-platform-user-create Create a new user in Platform

- delinea-platform-user-delete Delete user by ID from Platform

- delinea-platform-user-get Fetches a Platform user by uuid or upn

- delinea-platform-user-update Update a single user by ID in Platform

- delinea-platform-get-all-users Fetches all Platform user

- delinea-platform-get-user-searchbytext Retrieve Platform Users by Search Text