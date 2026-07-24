## Cisco Email Threat Defense (ETD) Configuration

To configure this integration, you need API credentials from your Cisco Email Threat Defense (ETD) tenant.

### Prerequisites

- Cisco Email Threat Defense (ETD) tenant
- API Key
- Client ID
- Client Secret
- ETD Base URL

### Obtain API Credentials

1. Sign in to the Cisco Email Threat Defense administrator portal.
2. Navigate to **Administration** > **API Applications**.
3. Create a new API application or select an existing application.
4. Copy the following credentials:
   - API Key
   - Client ID
   - Client Secret
5. Enter these values in the Cortex XSOAR integration configuration.

### Configure the Integration

Configure the following parameters when creating the integration instance:

- **ETD Base URL** – Base URL of your Cisco Email Threat Defense (ETD) tenant (for example, `https://api.<region>.emailthreatdefense.com`).
- **API Key** – API key used to authenticate requests.
- **Client ID** – OAuth client identifier.
- **Client Secret** – OAuth client secret.
- **First Fetch Time** – Time from which incidents are fetched during the initial execution.
- **Max Fetch** – Maximum number of incidents to fetch during each polling cycle.
- **Fetch Incidents** – Enable to automatically fetch ETD message events and create incidents in Cortex XSOAR.
- **Use system proxy settings** – Use the proxy configured on the Cortex XSOAR server.
- **Trust any certificate (not secure)** – Disable SSL certificate validation. Enable this option only when required for testing or trusted environments.

### Notes

- This integration retrieves **ETD message events** and creates incidents in Cortex XSOAR.
- Incident polling runs according to the configured **Incident Fetch Interval**.
- Ensure the configured API application has permission to access ETD message logs and perform message remediation operations.