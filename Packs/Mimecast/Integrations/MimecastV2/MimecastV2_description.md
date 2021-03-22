1. In order to refresh token / discover auth types of the account / create new access & secret keys, 
you are required to provide: App ID, Account email address & password.
These parameters support the following integration commands: 
mimecast-login -> fetches new access key & secret key
mimecast-discover -> lists supported auth types of user
mimecast-refresh-token -> refreshes the validity duration of access key & secret key (3 days)

2. In order to use the rest of the commands, you are required to provide: App ID, App Key, Access Key & Secret Key.
For detailed information about creating these fields, please refer to the [Mimecast Documentation](https://www.mimecast.com/tech-connect/authentication-scripts-server-apps/).

3. Fetch Incidents - the integration has the ability to fetch 3 types of incidents: url, attachment & impersonation.
In order to activate them first tick "fetch incidents" box, then tick the relevant boxes for each fetch type you want.