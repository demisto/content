Thycotic Secret Server is the only fully featured Privileged Account Management (PAM) solution available both on premise and in the cloud. It empowers security and IT ops teams to secure and manage all types of privileged accounts and offers the fastest time to value of any PAM solution. This integration was integrated and tested with version 6.0 of Thycotic.

To use this integration, you must have an account on your Thycotic server.

As required parameters, you must specify:

**Server URL** - URL Thycotic server, for example https://example.com/SecretServer.

Credentials for logging into Thycotic server.

**Username** - username to authenticate to Secret Server

**Password** - password to authenticate to Secret Server

You can pre-add them to the Credential or usage input Username and Password.

Use check box **Trust any certificate (not secure)** for insecure connections.

Use check box **Use system proxy settings** for proxy.

If you want to use the function of synchronizing secrets stored in Thycotic server, check the box and fill in the field with a list of the names of the secrets separated by commas.

Use the **TEST** button to check if the parameters for integration are correct. In case of successful authentication on the Thycotic server and correct filling of all other parameters, you will receive a response **Success**.

This integration performs some REST API transfers to the Thycotic server, the full description of which is given in the server documentation.

The following commands are implemented:

- thycotic-folder-create Create a new Secret folder

- thycotic-folder-delete Delete a folder by folder ID

- thycotic-folder-search Search folder by folder name

- thycotic-folder-update Update a single secret folder by ID

- thycotic-secret-checkin Check In a secret

- thycotic-secret-checkout Check Out a Secret

- thycotic-secret-create Create a new Secret

- thycotic-secret-delete Delete secret

- thycotic-secret-get Get secret object by ID secret

- thycotic-secret-password-get Retrieved password from secret

- thycotic-secret-password-update Update password for a secret by ID

- thycotic-secret-rpc-changepassword Change a secret's password

- thycotic-secret-search Search secret ID by multiply parameters

- thycotic-secret-search-name Search ID secret by Name

- thycotic-secret-username-get Retrieved username from secret

- thycotic-user-create Create a new user

- thycotic-user-delete Delete user by ID

- thycotic-user-search Search, filter, sort, and page users

- thycotic-user-update Update a single user by ID
