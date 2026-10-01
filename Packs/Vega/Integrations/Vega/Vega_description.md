## Vega Integration Setup

### Authentication

To connect to the Vega platform, you need an **Access Key ID** and an **Access Key**.

1. Log in to your Vega console.
2. Navigate to **Settings** > **Machine Users** / **API Keys**.
3. Generate or retrieve an **Access Key ID** and **Access Key** for your machine user.
4. Copy the **Access Key ID** and **Access Key** and paste them into the respective configuration parameters of this integration.

### Session Management

The integration automatically performs authentication using the `login_machine` endpoint.
It retrieves a JSON Web Token (`session_jwt`) and caches it in integration context. The cached token is reused for all subsequent API requests. The token will only be refreshed once it is close to expiring (within a 5-minute safety margin), ensuring minimal login requests are sent to the Vega API.

### Ingestion Settings

You can configure the integration to fetch alerts, incidents, or both using the **Vega Entities to fetch** parameter.

- **Alerts**: Fetches Vega alerts. You can filter the fetched alerts by specific severities (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), statuses (`Open`,`In Progress`, `Peer Review`, `Resolved`), and verdicts (`Malicious`, `Suspicious`, `Benign`, `Inconclusive`, `N/A`).
- **Incidents**: Fetches Vega incidents. You can filter the fetched incidents by specific severities (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), user statuses (`Open`, `In Review`, `On Hold`, `Resolved`), investigation statuses (`Pending`/`NEW`, `Investigating`, `Completed`, `Failed`), and verdicts (`Malicious`, `Suspicious`, `Benign`, `Inconclusive`, `N/A`). If a status filter is left empty, all values for that filter are fetched.
- **Include alert metadata on incidents**: When enabled, each fetched incident stores the full metadata of its related alerts. This can make incidents large and slow to open. Leave it disabled and run `vega-get-alert-metadata` in the War Room when you need that metadata.
- **Backfill Days**: Select how many days before today to retrieve alerts and incidents on the very first run (0–365). Use `0` for today only; the default is `30`.
- **Fetch alerts and incidents by ID**: Enable this on a second instance. Fetch ignores the other Collect filters and creates investigations only for the comma-separated UUIDs in **Alert IDs to fetch** and **Incident IDs to fetch**. An ID already in Cortex XSOAR is created again. Run `vega-reconcile-incidents` first and paste the missing IDs.

### Mirroring

- **Vega to Cortex XSOAR** mirroring is always enabled for fetched Vega alerts and incidents.
- **Cortex XSOAR to Vega** mirroring is controlled by **Enable XSOAR to Vega mirroring** in the **Autoclosure** section (enabled by default).
- Mirrored fields for alerts: status, severity, verdict, verdict reasoning, and comments.
- Mirrored fields for incidents: severity, user status, verdict, verdict reasoning, and comments. Investigation status is synced from Vega and is not sent back on update.
- Use the **Vega New Comment** field in the Comment section to add a comment from Cortex XSOAR that will be created in Vega.
