## Brandefense Integration for Cortex XSOAR

### Prerequisites
- A Brandefense account with API access enabled.
- An API Bearer Token generated from the Brandefense platform.

### How to Get Your API Key
1. Log in to your Brandefense account at [https://app.brandefense.io](https://app.brandefense.io).
2. Navigate to **Settings** → **API Tokens**.
3. Click **Create New Token** and configure the required scopes:
   - **Asset Read** — For asset-related commands
   - **Incident Read** — For incident fetching and queries
   - **Incident Create** — For creating incidents
   - **Intelligence Read** — For intelligence reports
   - **Threat Intelligence Read** — For IoC and threat intelligence data
   - **Threat Search** — For CTI threat search capability
   - **Indicator Read** — For indicator retrieval
   - **Referrer Log Create** — For phishing monitoring
4. Copy the generated token and paste it into the **API Key** field in the integration configuration.

### Configuration Parameters
| Parameter | Description | Required |
|-----------|-------------|----------|
| **Server URL** | Brandefense API URL (default: `https://api.brandefense.io`) | Yes |
| **API Key** | Your Brandefense API Bearer Token | Yes |
| **Trust any certificate** | Skip SSL certificate verification (not recommended for production) | No |
| **Use system proxy settings** | Route requests through the system proxy | No |
| **Fetch incidents** | Enable automatic incident fetching | No |
| **Incidents Fetch Interval** | How often to fetch new incidents (in minutes) | No |
| **First time fetching** | How far back to fetch incidents on the first run (e.g., `3 days`) | No |
| **Fetching Issue Types** | Choose to fetch Incidents, Intelligence, or both | Yes |

### Fetching Incidents
When **Fetch incidents** is enabled, the integration periodically polls the Brandefense API for new incidents and intelligence reports. You can filter by:
- **Incident Category** — Brand Monitoring, Executive Protection, etc.
- **Incident Module** — Breach Monitoring, Phishing, Dark Web Intelligence, etc.
- **Incident Status** — OPEN, IN_PROGRESS, CLOSED, etc.
- **Incident Rules** — Specific detection rule types
- **Intelligence Category** — Strategic, Tactical, Operational Intelligence, etc.
