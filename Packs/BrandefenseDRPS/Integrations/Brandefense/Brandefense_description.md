## Get Your API Key

### Prerequisites

- A Brandefense account with API access enabled.
- An API Bearer Token generated from the Brandefense platform.

### Steps

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