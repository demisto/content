## Obtain Authentication Parameters

The Censys API v3 integration supports two authentication types, selected using the **Authentication Type** parameter:

- **OAuth 2.0**: Uses the **Client ID** and **Client Secret** of a Censys service account.
- **API Token** (default): Uses a Personal Access Token (PAT).

For both authentication types, you also need your Organization ID.

### Step 1: Create Authentication Credentials

#### OAuth 2.0: Create a Service Account

**Prerequisites**: Your organization must be on the Censys **Search** or **Core** plan, and your account must have the **Platform Admin** role to create service accounts.

1. Log in to the [Censys Platform](https://platform.censys.io/).
2. Navigate to **Organization Settings** > **Service Accounts**.
3. Click **+ Create service account**.
4. Enter a name and select the module roles for the service account. At least one module role is required. Grant only the permissions the integration needs.
5. Click **Create service account**.
6. Copy the **Client Secret** and store it in a secure location. It will not be shown again.
7. Note the **Client ID**. It can be retrieved from the **Service Accounts** page at any time.
8. In the integration configuration, select **OAuth 2.0** as the **Authentication Type** and enter the **Client ID** and **Client Secret**.

**Note**: If the client secret is rotated in the Censys Platform, update the **Client Secret** in the integration configuration and click **Test**. The old secret stops working after rotation.

For more information, see [Censys Platform Service Accounts](https://docs.censys.com/docs/platform-service-accounts).

#### API Token: Create a Personal Access Token

1. Log in to the [Censys Platform](https://platform.censys.io/).
2. Navigate to **Account Management** > **Personal Access Tokens**.
3. Click **Create New Token**.
4. Provide a **Token Name** (required) and an optional description.
5. Click **Create**.
6. Copy the token value from the confirmation dialog and store it in a secure location.
7. In the integration configuration, select **API Token** as the **Authentication Type** and enter the token in the **API Token** parameter.

### Step 2: Find Your Organization ID

1. In the Censys Platform web console, ensure that you have your **Starter** or **Enterprise** account selected.
2. Your **Organization ID** is provided in the browser URL after `org=`. This ID is mandatory for API requests to identify entitlements and billing details.

## Rate limit

Censys rate limits to 10 queries a day per IP for unauthenticated clients, and variable numbers per day depending on your pricing tier. <https://search.censys.io/subscriptions>

## IP reputation command

- **Determine IP score using Censys Host Reputation data**: Scores the IP as Malicious, Suspicious or Benign based on the Censys host reputation label (`host.reputation.label`).
- **Use Censys Host Enrichment API for ip command**: Retrieves IP data from the host enrichment API (enabled by default). IPs that fail enrichment fall back to the search API. The ***ip*** command's `use_enrichment_endpoint` argument overrides this parameter.
- **Determine IP score using Censys Labels**: Scores the IP using host labels (`host.labels.value`) and service labels (`host.services.labels.value`) against the configured malicious/suspicious labels and thresholds. Thresholds count distinct labels across the host and its services. Labels that are not listed in the drop-down can be typed in manually.
- **When both scoring options are enabled**: The higher of the two scores is applied. If both give the same score, both reasons are shown in the description.

Once the integration instance is configured, it will be used to populate the Censys SOAR dashboard.
