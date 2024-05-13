1. To use API 2.0 you must provide a Client ID and Client Secret and make sure the Use OAuth 2.0 checkbox is checked and the BaseUrl is https://api.services.mimecast.com.
How to generate API 2.0 Client ID + Client Secret:
From the Mimecast admin console navigate to: Admin | Services | API and Platform Integrations | Available integrations, locate the Mimecast API 2.0 tile and select Generate Keys.

2. In API 1.0 in order to refresh token / discover auth types of the account / create new access & secret keys, 
you are required to provide: App ID, Account email address & password, and BaseUrl is https://api.mimecast.com and make sure the Use OAuth 2.0 checkbox is unchecked.
These parameters support the following integration commands: 
mimecast-login -> fetches new access key & secret key
mimecast-discover -> lists supported auth types of user
mimecast-refresh-token -> refreshes the validity duration of access key & secret key (3 days)

3. In order to use the rest of the commands, you are required to provide: App ID, App Key, Access Key & Secret Key.
For detailed information about creating these fields, please refer to the [Mimecast Documentation](https://integrations.mimecast.com/documentation/api-overview/authentication-scripts-server-apps/).

4. Fetch Incidents - the integration has the ability to fetch 3 types of incidents: url, attachment & impersonation.
In order to activate them first tick "fetch incidents" box, then tick the relevant boxes for each fetch type you want.