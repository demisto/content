## Obtain Authentication Parameters

To successfully connect to the Censys Platform API v3, the integration requires a Personal Access Token (PAT) and an Organization ID.

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

Censys API provides reputation data exclusively to paying customers. When set to True, the integration will use labels to determinate reputation on IPs.
