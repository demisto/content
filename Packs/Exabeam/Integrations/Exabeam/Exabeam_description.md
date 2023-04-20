The Exabeam Security Management Platform provides end-to-end detection, User Event Behavioral Analytics and SOAR.

### Authentication Methods
There are 2 authentication methods:
 - **API Token** - API token should be entered in the “API Token” parameter. In order to use the “Fetch Incident” functionality in this integration, the username must be provided also in the “Username” parameter.
 - **Basic Authentication** - Providing Username and password in the corrsponding parameters in the configuration. This method also allows fetching incidents.
 - ***Deprecated***:
 API Key entered in the “password” parameter and `__token` in the username parameter. This method won’t allow fetching incidents.

### Generate a Cluster Authentication Token

1. Navigate to Settings > Admin Operations > Cluster Authentication Token.

2. At the Cluster Authentication Token menu, click the blue `+` button.
   
3. In the **Setup Token** menu, fill in the **Token Name**, **Expiry Date**, and select the **Permission Level**(s).

4. Click **ADD TOKEN** to apply the configuration.

For additional information, refer to [Exabeam Administration Guide](https://docs.exabeam.com/en/advanced-analytics/i54/advanced-analytics-administration-guide/113254-configure-advanced-analytics.html#UUID-70a0411c-6ddc-fd2a-138d-fa83c7c59a40).
