The feed allows customers to pull indicators of compromise from cyber incidents (IP addresses, URLs, domains, CVEs, and file hashes).

## CYJAX API token

1. Log in to [CYJAX threat intelligence portal](https://cymon.co).
2. On the top navigation bar, hover the cursor over your user icon and go to **Profile Settings**.
3. Open the API tokens tab.
4. Generate a new token and enable the Indicators API scope.
5. Record the API token, as it will not be accessible after the window is closed.

## Feed installation

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **Cyjax Feed**.
3. Click **Add instance** to create and configure a new integration instance.

## Configuration

1. Enter feed name, e.g., `CYJAX Feed`.
2. API URL: `https://api.cymon.co/v2`.
3. Enter CYJAX API token.
4. Set proxy if required by your installation.
5. Indicator reputation (the reputation assigned to the indicators fetched from this feed; the default is Suspicious).
6. Source reliability: A - Completely reliable.
7. Traffic Light Protocol Color - The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed.
8. Use CYJAX feed TLP (selected by default) - Whether to use the TLP set by CYJAX. This will override the TLP set above.
9. Set feed tags (optional, comma-delimited, e.g., MyTag, YourTag).
10. Set Indicator Expiration Method (default is never).
11. Set fetch interval (default is to fetch every 1 hour).
12. First fetch time. The time interval for the first fetch (retroactive). The default is 3 days.
13. Test connection.
14. Click done to save.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### !cyjax-get-indicators

***
Get indicators from the CYJAX API.

| **Argument** | **Description** | **Required** |
| --- | --- | --- |
| since | The start date time in ISO 8601 format | Optional |
| until | The end date time in ISO 8601 format | Optional |
| type | The indicator type. If not specified all indicators are returned. Allowed values are IPv4, IPv6, Domain, Hostname, Email, FileHash-SHA1, FileHash-SHA256, FileHash-MD5, FileHash-SSDEEP | Optional |
| source_type | The indicator source type. Allowed values are incident-report, my-report | Optional |
| source_id | The indicator source ID | Optional |
| limit | The maximum number of indicators to get. The default value is 50. | Optional |

Example: `!cyjax-get-indicators since=2020-10-23T00:00:00 type=IPv4`

### !cyjax-indicator-sighting

***
Get the CYJAX sighting of an indicator.

| **Argument** | **Description** | **Required** |
| --- | --- | --- |
| value | The indicator value | Required |

Example: `!cyjax-indicator-sighting value=176.117.5.126`

### !cyjax-unset-indicators-last-fetch-date

***
Unset the indicators feed last fetch date. Should only be used if a user needs to use the `re-fetch` button
and wants to fetch old indicators from CYJAX. The next feed will use the date set in first_fetch (default is the last 3 days).
