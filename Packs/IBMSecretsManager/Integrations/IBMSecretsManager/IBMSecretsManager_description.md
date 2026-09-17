## IBM Secrets Manager

Collect IBM Secrets Manager audit / Activity Tracker events (via IBM Cloud Logs) into Cortex.

### Prerequisites

This integration uses IBM Cloud IAM authentication for IBM Cloud Logs authorization.
The owning identity must be assigned one or more IAM access roles that include the following actions:

- `logs.logs-data-api-high.read`
- `logs.logs-data-api-low.read`

For more information, see the [IBM Cloud Logs query permissions](https://cloud.ibm.com/docs/apis/logs-service-api#query-permissions).

### Obtain an IAM API key

1. In the IBM Cloud console, go to **Manage → Access (IAM) → API keys**.
2. Select **Create** and give the key a name; copy the generated API key value (shown once).
3. Ensure the owning identity has IBM Cloud Logs read/query access for the audit-log collection.

### Find your service endpoints

- **Cloud Logs Server URL**: `https://{instance_guid}.api.{region}.logs.cloud.ibm.com` — shown on the Cloud Logs instance's **Endpoints** page (both instance GUID and region are per-instance).

### Notes

- The IAM access token is short-lived (~1 hour). The integration is stateless and exchanges the API key for a fresh Bearer token on each run.
- For non-default IAM environments, override the **IAM URL** advanced parameter.