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
- **Incidents**: Fetches Vega incidents. You can filter the fetched incidents by specific severities (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), statuses (`New`, `Investigating`, `On Hold`, `External Escalation`, `Resolved`, `Reopened`, `Review Recommended`, `Response Required`, `Under Review`), and verdicts (`Malicious`, `Suspicious`, `Benign`, `Inconclusive`, `N/A`).
- **Backfill Days**: Select how many days before today to retrieve alerts and incidents on the very first run (0–365). Use `0` for today only; the default is `30`.

### Mirroring

- **Vega to Cortex XSOAR** mirroring is always enabled for fetched Vega alerts and incidents.
- **Cortex XSOAR to Vega** mirroring is controlled by **Enable XSOAR to Vega mirroring** in the **Autoclosure** section (enabled by default).
- Mirrored fields for alerts: status, severity, verdict, verdict reasoning, and comments.
- Mirrored fields for incidents: severity, status, verdict, verdict reasoning, and comments.
- Use the **Vega New Comment** field in the Comment section to add a comment from Cortex XSOAR that will be created in Vega.

### Vega Recommended Actions

When Vega incidents are ingested, the integration maps the API `recommendedActions` field to the **Vega Recommended Actions** incident grid field. Each row includes:

- **Name**: The recommended action title.
- **Description**: A human-readable explanation of the action.
- **Action Key**: The Vega action identifier (for example, `block_ip`, `revoke_user_sessions`, `reset_user_password`).
- **Target Params**: The action parameters returned by Vega (for example, `user_id` or `ip`).

The integration normalizes recommended action descriptions during ingestion by ensuring each description ends with a trailing newline. This prevents long descriptions from being truncated in the XSOAR grid UI and allows the full text to wrap and display correctly.

When `recommendedActions` is empty (`[]`) or missing, the grid shows a single row with **No recommended Actions found**.
