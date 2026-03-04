Two-factor authentication (2FA) must be enabled on the console and configured for the account accessing the API.

<~PLATFORM>

## How to fetch assets and vulnerabilities

The integration uses the **fetch-assets** mechanism to periodically collect assets and vulnerabilities from Rapid7 InsightVM.

To enable asset fetching:
1. Check the *Fetches assets* checkbox in the integration configuration.
2. Configure the *Assets Fetch Interval* parameter to set how often assets are fetched (default: 24 hours).

The fetched data may take up to 10 minutes to be ingested into the tenant after each fetch cycle.
</~PLATFORM>
