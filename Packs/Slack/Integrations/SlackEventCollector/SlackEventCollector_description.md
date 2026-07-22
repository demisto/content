Audit Logs API is only available to Slack workspaces on an Enterprise Grid plan, meaning, this Integration will *not* work for workspaces on a Free, Standard, or Business+ plan. For more information about the Audit Logs API, visit the [Slack API Documentation](https://api.slack.com/admins/audit-logs).

To configure an instance of Slack Event Collector, a Slack **User Token** with the `auditlogs:read` permissions must be obtained.

### Obtain a User Token
**Important**: The following steps must be done by the **Owner** of the Enterprise Grid organization.
1. Create a Slack app [here](https://api.slack.com/apps?new_app=1). By clicking the **Create App** button, you will be redirected to its settings page.
2. Using the left navigation bar, go to **OAuth & Permissions**.
   Scroll down to the **Scopes** section and add the `auditlogs:read` User Token Scope to your app.
3. Using the left navigation bar, go to **Manage Distribution**.
   * **Activate Public Distribution** by make sure all sections under **Share Your App with Other Workspaces** have the green check. Then click the **Activate Public Distribution** button.
   * Under the **Share Your App with Your Workspace** section, copy the **Sharable URL** and paste it into a browser to initiate the OAuth handshake that will install the app on your organization.
   * **Check the dropdown in the upper right of the installation page to make sure you are installing the app on the Enterprise Grid organization, not an individual workspace within the organization.**
4. Once your app completes the OAuth flow, you will be granted an OAuth token that can be used for calling all of the Audit Logs API methods for your organization. The token should start with `xoxp-`.
