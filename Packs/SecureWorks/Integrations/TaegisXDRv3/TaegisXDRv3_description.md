## Secureworks Taegis XDR Help

This integration connects Cortex XSOAR to the Secureworks Taegis XDR platform for case ingestion, bi-directional mirroring, assignee/status management, and threat investigation.

### Authentication

The integration authenticates with OAuth 2.0 using the **client credentials** grant. It exchanges the configured Client ID and Client Secret for a short-lived bearer token against your tenant's `/auth/api/v2/auth/token` endpoint, and refreshes that token automatically as it expires. No interactive login, refresh token, or user session is involved, so the credential's own assigned role is what governs everything the integration can do.

### Required Taegis Role

Two different roles are involved, and it is worth keeping them apart:

- **To create the credential**, you need the **Tenant Admin** or **Tenant Analyst** role in the Taegis tenant.
- **The role assigned to the credential itself** is what limits the integration at runtime. This is the one to keep least-privilege.

**Tenant Analyst is the minimum role required, and it covers every command in this integration.** Taegis offers Tenant Admin, Tenant Analyst, Tenant Auditor (Read Only), and Tenant Responder; Tenant Analyst is the least-privilege role that supports the full command set:

- Fetch cases and alerts, including the initial fetch and ongoing mirroring.
- Update cases — status, assignee, key findings, and comments — in both directions.
- Archive, unarchive, and close cases.
- Isolate an asset with ***taegis-isolate-asset***, covered by the **Able to trigger remediation response actions** permission.
- Execute an existing Taegis XDR Automation with ***taegis-execute-playbook***, covered by the **Able to execute a Playbook Instance** permission.

There is one operational prerequisite worth knowing before you rely on ***taegis-execute-playbook***. Tenant Analyst can *execute* a Playbook Instance but cannot *create* one, and it cannot execute a Playbook definition directly. This integration calls the `executePlaybookInstance` mutation, so it needs the Automation to already exist as a configured Playbook Instance in Taegis. Have a Tenant Admin create and configure the Automation once; afterwards an Analyst-scoped credential can trigger it from Cortex XSOAR indefinitely. Pass that Playbook Instance ID — not a Playbook ID — as the command's `id` argument.

Use Tenant Admin only if you also want Cortex XSOAR to create or modify Automations, which this integration does not do. Grant the credential access only to the tenants this Cortex XSOAR instance is meant to act against.

Some Taegis operations require **privileged** client credentials rather than standard ones. If a command returns an authorization error while the rest of the integration works, see [Create Privileged Client Credentials](https://docs.taegis.secureworks.com/apis/api_authenticate/#create-privileged-client-credentials-optional) and re-create the credential as privileged.

### Generate a Client ID and Client Secret

1. From the Taegis Menu, select **Tenant Settings** > **Manage API Credentials**.
2. Select **Add Credential** from the top right of the page.
3. In the **Add API Credential** modal, enter a name for the new credential.
4. Assign the credential the least-privilege role it needs — **Analyst** for normal operation, as described above.
5. Select **Submit**.

The system generates a **Client ID** and **Client Secret**. The Client Secret is displayed only once, immediately upon creation — copy and securely store it, as it cannot be retrieved again.

See [Adding API Credentials](https://docs.taegis.secureworks.com/apis/api_authenticate/#adding-api-credentials) for more detail, including how to create privileged credentials or generate credentials via the CLI.

### Base URLs

Taegis XDR is hosted on region-specific endpoints. Both URLs below must match your tenant's region and must **not** include a trailing slash:

- **API base URL**: the REST/GraphQL API endpoint for your region, e.g. `https://api.ctpx.secureworks.com`.
- **XDR base URL**: the Taegis XDR web UI endpoint for your region, e.g. `https://ctpx.secureworks.com`. Used to build clickable links back to investigations and alerts.

See [XDR GraphQL APIs Authentication](https://docs.taegis.secureworks.com/apis/api_authenticate/#part-1-create-client-credentials) for the current list of region endpoints, since new regions are added over time.

### Tenant ID

Optional. If your API credentials are scoped to a single tenant, this field can usually be left blank. If you use multi-tenant credentials, supply the specific Tenant ID you want this instance to act against.
