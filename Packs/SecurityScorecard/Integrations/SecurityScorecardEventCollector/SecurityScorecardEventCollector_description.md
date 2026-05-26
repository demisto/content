## SecurityScorecard Event Collector

This integration collects history events from SecurityScorecard for ingestion into Cortex XSIAM.

### How to Configure the Integration Instance

#### Prerequisites

You need a SecurityScorecard API token to authenticate with the API.

#### Creating an API Token

1. In SecurityScorecard, click your profile avatar and select **My Settings**.
2. Select the **API** tab in the left settings pane and then click **Generate New API Token**.
3. Click **Confirm** to generate the token.
4. Copy the token and store it securely.

> **Note:** API tokens do not expire on their own. Creating a new token invalidates any previously created token. You will need to replace the older API key with the new one for your integrations to continue working.

#### Configuration Parameters

| Parameter | Description | Required |
|---|---|---|
| **Server URL** | The SecurityScorecard API base URL. Default: `https://api.securityscorecard.io` | Yes |
| **API Token** | The API token for authenticating with SecurityScorecard. | Yes |
| **Scorecard Identifier** | The domain identifier for the scorecard (e.g., `google.com`). | Yes |
| **Fetch events** | Whether to fetch events automatically. | No |
| **Maximum number of events per fetch** | Maximum number of events to fetch per cycle (default: 1000). | No |
| **First fetch time** | How far back to fetch events on the first run (e.g., `3 days`, `7 days`). | No |

### Rate Limits

The SecurityScorecard API enforces rate limits to ensure system stability:

- Each client can make up to **5,000 requests per hour** over a rolling 60-minute window.
- If the rate limit is exceeded, the API returns a **429 Too Many Requests** response with a `Retry-After` header.
- The integration handles rate limits gracefully by sending collected events to Cortex XSIAM and waiting for the next fetch cycle.
