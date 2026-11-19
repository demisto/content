## Cisco Webex Event Collector v2

This integration is configured from the **Cisco Webex** connector page. It uses a single Webex OAuth 2.0 integration app instead of separate Admin and Compliance Officer apps.

### Create the Webex integration app

1. Sign in to the [Webex Developer Portal](https://developer.webex.com/my-apps) with a user that has the **Full Administrator** and **Compliance Officer** roles.
2. Create a new **Integration** and add the connector's callback URL as a **Redirect URI**.
3. Select the scopes for the event types you want to collect:
   - Admin Audit Events and Security Audit Events: `audit:events_read`, `spark:kms`
   - Events: `spark-compliance:events_read`, `spark:kms`
4. Copy the **Client ID** and **Client Secret** into the connector, then select **Authorize** and approve the app.

### Organization ID

Admin and security audit events require the Webex organization ID. In Webex Control Hub, go to **Account** and copy the **Organization ID**.

### Security audit events

Security audit events require an active Webex **Pro Pack** license and the **Allow user authentication data** setting in Control Hub (**Organization Settings** > **Security**).

Events are stored in the `cisco_webex_v2_raw` dataset.
