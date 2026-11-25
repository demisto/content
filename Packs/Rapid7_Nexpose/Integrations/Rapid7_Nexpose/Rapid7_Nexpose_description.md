Two-factor authentication (2FA) must be enabled on the console and configured for the account accessing the API.

<~PLATFORM>

## How to fetch assets and vulnerabilities

This integration uses the **fetch-assets** mechanism to periodically collect assets and vulnerabilities from Rapid7 InsightVM.

To enable asset fetching:
1. In the integration settings pane in your tenant, check the **Fetches assets** checkbox.
2. In the **Assets Fetch Interval** parameter, specify how often to fetch assets. The default is every 24 hours.
3. (Optional) In the **Lookback (days)** parameter, specify how many days back to collect assets with a completed scan and vulnerability findings. The default is 100 days. A smaller value reduces the load on the Rapid7 Security Console.
The fetched data may take up to 10 minutes to be ingested into the tenant after each fetch cycle.
</~PLATFORM>
