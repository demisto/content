# Github Event Collector

Integration with Github using REST API to get audit logs for an organization.

## Server URL

Specify the endpoint for fetching audit logs; replace the `${ORGANIZATION}` value with your organization: `https://api.github.com/orgs/${ORGANIZATION}/audit-log`

## API Token

1. [Verify your email address](https://docs.github.com/en/enterprise-cloud@latest/account-and-profile/how-tos/email-preferences/verifying-your-email-address), if it has not been verified yet.
2. In the upper-right corner of any page on GitHub, click the user profile picture, then click **Settings**.
3. In the left sidebar, click **Developer settings**.
4. In the left sidebar, under **Personal access tokens**, click **Tokens (classic)**.
5. Select **Generate new token**, then click **Generate new token (classic)**.
6. In the "**Note**" field, give the token a descriptive name.
7. Select a suitable **Expiration** date by choosing the default option or click **Custom** to enter a specific date.
8. Select the **Scopes** to grant this token. To fetch audit logs, ensure the token has the `read:audit_log` permission scope.
9. Click **Generate token**.
10. Save the token in a safe location and use it to configure an instance of this integration.
11. Test the configuration and save the integration instance.

For more information, refer to the documentation on [creating a Github personal access token (classic)](https://docs.github.com/en/enterprise-cloud@latest/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token-classic) and [accessing the Github audit logs of an organization](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise).

## Permissions

To fetch audit logs, ensure the API Token has the `read:audit_log` permission scope.
