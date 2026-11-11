## Obtain Authentication Parameters

To connect to the Censys API v3 integration, you need your Personal Access Token (PAT) and Organization ID.

### Step 1: Create a Personal Access Token
1. Log in to the [Censys Platform](https://platform.censys.io/).
2. Navigate to **Account Management** > **Personal Access Tokens**.
3. Click **Create New Token**.
4. Provide a **Token Name** (required) and an optional description.
5. Click **Create**.
6. Copy the token value from the confirmation dialog and store it in a secure location.

### Step 2: Find Your Organization ID
1. In the Censys Platform web console, ensure that you have your **Starter** or **Enterprise** account selected.
2. Your **Organization ID** is provided in the browser URL after `org=`. This ID is mandatory for API requests to identify entitlements and billing details.

## Rate limit

Censys rate limits to 10 queries a day per IP for unauthenticated clients, and variable numbers per day depending on your pricing tier. <https://search.censys.io/subscriptions>

## IP reputation command

- **Determine IP score using Censys Host Reputation data**: Scores the IP as Malicious, Suspicious or Good based on the Censys host reputation label (`host.reputation.label`).
- **Use Censys Host Enrichment API for ip command**: Retrieves IP data from the host enrichment API (enabled by default). IPs that fail enrichment fall back to the search API. The ***ip*** command's `use_enrichment_endpoint` argument overrides this parameter.
- **Determine IP score using Censys Labels**: Scores the IP using host labels (`host.labels.value`) and service labels (`host.services.labels.value`) against the configured malicious/suspicious labels and thresholds. Thresholds count distinct labels across the host and its services. Labels that are not listed in the drop-down can be typed in manually.
- **When both scoring options are enabled**: The higher of the two scores is applied. If both give the same score, both reasons are shown in the description.

Once the integration instance is configured, it will be used to populate the Censys SOAR dashboard.
