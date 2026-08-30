Fetches indicators of compromise from the Haseen STIX 2.x threat-intelligence feed and parses them into Cortex XSOAR indicators.
This integration was integrated and tested with the Haseen STIX 2.1 threat-intelligence feed.

## Configure Haseen Threat Intel in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Tags | Supports CSV values. | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Incremental Feed | Incremental feeds pull only new or modified indicators that have been sent from the integration. | False |
| The maximum number of indicators that can be fetched per fetch. If this field is left empty, there will be no limit on the number of indicators fetched. | The maximum number of indicators to fetch per iteration. Leave empty to fetch all indicators \(no limit\). | False |
| First Fetch Time | The time interval for the first retroactive fetch, formatted as &lt;number&gt; and &lt;time unit&gt; of type minute/hour/day. For example, 1 minute, 12 hours. | False |
| Feed Fetch Interval | How often to fetch indicators in minutes. Haseen rate-limits the feed to 2 requests per hour, so set this to 60 or higher to avoid 429 throttling. | False |
| Server URL | The full STIX export URL, including the export ID. Example: `https://share.haseen.gov.sa/api/v1/threat-intelligence/export/1234`. | True |
| API Token | The API token from Haseen \(settings page\). Sent as a `token` query parameter on every request \(not a Bearer header\). Enter it in the password field. | True |
| Basic Auth Credentials \(optional\) | For exports that require Basic authentication in addition to the token. Username is the account email; password is the API token. | False |
| Trust any certificate \(not secure\) |  | False |
| Use system proxy settings |  | False |

## What this integration does

The integration operationalizes Haseen intelligence inside Cortex XSOAR through an automated pipeline:

1. **Automated Feed Retrieval** — downloads the Haseen STIX 2.x bundle from the configured export endpoint once new indicators are added/updated.
2. **STIX Parsing** — parses the STIX content and identifies actionable intelligence objects (indicators, malware, threat actors, relationships).
3. **Indicator Extraction** — extracts relevant indicators and observables from the STIX bundle.
4. **Normalization** — converts Haseen intelligence into XSOAR-native indicator formats.
5. **Deduplication** — prevents duplicate indicators from being created within the platform (seen-indicator watermark across fetches).
6. **Enrichment** — applies metadata such as source, feed name, confidence, labels, TLP, and intelligence context.
7. **Operationalization** — makes threat intelligence immediately available to detection, threat hunting, incident response, and automated correlation use cases.

### Supported indicator types

- **Network** — IPv4, IPv6, domains, URLs, FQDNs.
- **File** — MD5, SHA1, SHA256.
- **Threat context** — malware references, campaign information, threat attribution, intelligence metadata.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
