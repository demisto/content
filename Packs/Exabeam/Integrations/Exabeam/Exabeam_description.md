The Exabeam Security Management Platform provides end-to-end detection, User Event Behavioral Analytics and SOAR.

Full documentation for this integration is available in the [reference docs](https://xsoar.pan.dev/docs/reference/integrations/exabeam).


### Authentication Methods

This integration allows two methods for authentication:
1. User Credentials Authentication
2. Cluster Authentication Token

For the User Credentials Authentication, insert your credentials in the Username and Password parameters. 


### Authenticate with User Credentials

The cluster authentication token is used to verify identities between clusters that have been deployed in phases as well as HTTP-based log collectors. Each peer cluster in a query pool must have its own token. You can set expiration dates during token creation or manually revoke tokens at any time.

To generate a token:

1. Navigate to Settings > Admin Operations > Cluster Authentication Token.

2. At the Cluster Authentication Token menu, click the blue `+` button.
   
3. In the **Setup Token** menu, fill in the **Token Name**, **Expiry Date**, and select the **Permission Level**(s).

4. Click **ADD TOKEN** to apply the configuration.

For additional information, refer to [Exabeam Administration Guide](https://docs.exabeam.com/en/advanced-analytics/i54/advanced-analytics-administration-guide/113254-configure-advanced-analytics.html#UUID-70a0411c-6ddc-fd2a-138d-fa83c7c59a40).
