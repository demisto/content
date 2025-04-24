Follow these instructions to successfully instantiate an instance of the Netskope API v2 integration.
Enter an API token and your Server URL.

#### Follow these instructions to retrieve the API token:

1. Log in to your Netskope account as an administrator.
2. Click **Settings** in the left sidebar menu.
3. On the newly opened window, in the left sidebar, click **Tools** >> **REST API v2**.
4. On the REST API v2 page, click **NEW TOKEN**.
5. Click **ADD ENDPOINT** to add the following endpoints to your API token:
    - api/v2/events/data/application
    - api/v2/events/data/audit
    - api/v2/events/data/page
    - api/v2/events/data/network
    - api/v2/events/data/infrastructure
    - api/v2/events/data/alert
    - api/v2/policy/urllist (read + write permissions)
    - api/v2/policy/urllist/deploy (read + write permissions)
    - api/v2/scim/Users.
    - api/v2/events/dataexport/events/incident
    - api/v2/incidents/update
6. Make sure to fill in the **EXPIRE IN** and **TOKEN NAME** fields and click **SAVE**.
7. A new API token will be generated for you. Copy the generated API token and keep it secure.

Note that the API token is generated with permissions to the specified endpoints.

#### Find your Server URL:

The server URL consists of the Netskope account name and region.
For example, if your company account name in Netskope is `xsoar`, and your account provided region is `de`, then the Server URL configuration parameter would be `https://xsoar.de.goskope.com`.
