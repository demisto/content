The feed allows customers to pull indicators of compromise from cyber incidents (IP addresses, URLs, domains, CVE and file hashes).

## Cyjax API token
1. Login to [Cyjax threat intelligence portal](https://cymon.co).
2. On the top navigation bar, hover the cursor over your user icon and go to **Developer settings**.
3. Open personal access token tab.
4. Generate new token
5. Record the API token, as it will not be accessible after the window is closed.

## Feed installation
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **Cyjax Feed**.
3. Click **Add instance** to create and configure a new integration instance.

## Configuration
1. Enter feed name eg. `Cyjax Feed`
2. API URL `https://api.cyberportal.co`
3. Enter Cyjax API token
4. Set proxy if required by your installation
5. Indicator reputation (the reputation set to the indicators fetched from this feed, default is Suspicious)
6. Source reliability: A - Completely reliable
7. Traffic Light Protocol Color - The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed.
8. Use Cyjax feed TLP (selected by default) - Whether to use TLP set by Cyjax. Will override TLP set above.
9. Set feed tags. (optional)
10. Set Indicator Expiration Method (default is never)
11. Fetch interval (default is to fetch every 1 hour)
12. First fetch time. The time interval for the first fetch (retroactive). Default is 3 days.
13. Test connection.
14. Click done to save.

## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### !cyjax-get-indicators
***
Get indicators from Cyjax API

| **Argument** | **Description** | **Required** |
| --- | --- | --- |
| since | The start date time in ISO 8601 format | Optional |
| until | The end date time in ISO 8601 format | Optional |
| type | The indicator type. If not specified all indicators are returned. Allowed values are IPv4, IPv6, Domain, Hostname, Email, FileHash-SHA1, FileHash-SHA256, FileHash-MD5, FileHash-SSDEEP | Optional |
| source_type | The indicators source type. Allowed values are incidnet-report, my-report | Optional |
| source_id | The indicators source ID | Optional |

example: `!cyjax-get-indicators since=2020-10-23T00:00:00 type=IPv4`

### !cyjax-cyjax-indicator-sighting
***
Get Cyjax sighting of a indicator

| **Argument** | **Description** | **Required** |
| --- | --- | --- |
| value | The indicator value | Required |

example: `!cyjax-indicator-sighting value=176.117.5.126`
