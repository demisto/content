## Sophos Taegis XDR Help

This integration connects Cortex XSOAR to the Sophos Taegis XDR platform for case ingestion, bi-directional mirroring, assignee/status management, and threat investigation.

### Generate a Client ID and Client Secret

You must have the **Tenant Admin** or **Tenant Analyst** role in your Taegis tenant to create API credentials.

1. From the Taegis Menu, select **Tenant Settings** > **Manage API Credentials**.
2. Select **Add Credential** from the top right of the page.
3. In the **Add API Credential** modal, enter a name for the new credential.
4. Select **Submit**.

The system generates a **Client ID** and **Client Secret**. The Client Secret is displayed only once, immediately upon creation — copy and securely store it, as it cannot be retrieved again.

See [Adding API Credentials](https://docs.taegis.secureworks.com/apis/api_authenticate/#adding-api-credentials) for more detail, including how to create privileged credentials or generate credentials via the CLI.

### Base URLs

Taegis XDR is hosted on region-specific endpoints. Both URLs below must match your tenant's region and must **not** include a trailing slash:

- **API base URL**: the REST/GraphQL API endpoint for your region, e.g. `https://api.ctpx.secureworks.com`.
- **XDR base URL**: the Taegis XDR web UI endpoint for your region, e.g. `https://ctpx.secureworks.com`. Used to build clickable links back to investigations and alerts.

See [XDR GraphQL APIs Authentication](https://docs.taegis.secureworks.com/apis/api_authenticate/#part-1-create-client-credentials) for the current list of region endpoints, since new regions are added over time.

### Tenant ID

Optional. If your API credentials are scoped to a single tenant, this field can usually be left blank. If you use multi-tenant credentials, supply the specific Tenant ID you want this instance to act against.
