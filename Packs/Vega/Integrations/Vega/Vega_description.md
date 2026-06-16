## Vega Integration Setup

The Vega integration allows you to ingest alerts and incidents from the Vega platform using the GraphQL API.

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

Use `vega-update-alert` and `vega-update-incident` to push status, verdict, severity, and comment changes from Cortex XSOAR to Vega.