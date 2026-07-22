This integration fetches findings from completed Cymulate assessments as Cortex XSOAR incidents using the Cymulate V2 Assessment API.

## Configure Cymulate v3 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API token | Cymulate API token used for authentication \(sent as `x-token`\). | True |
| Base URL | Cymulate API base URL \(for example: `https://api.app.cymulate.com`\). | True |
| Trust any certificate (not secure) | If checked, SSL certificate verification is disabled. | False |
| Use system proxy settings | Use the system proxy settings for HTTP/S requests. | False |
| Fetch incidents | When enabled, fetches Cymulate assessment findings as Cortex XSOAR incidents. | False |
| Fetch category | **All** fetches all "Not Prevented" findings. **Threat Feed IOCs** fetches only findings tagged as Threat Feed IOC. Default: All. | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | First time to fetch incidents from. | False |
| Max Fetch | Maximum number of incidents to return per fetch run. Default: 25. | False |
| Incident type |  | False |

## Commands

This integration does not expose additional commands. It operates exclusively through the **fetch-incidents** mechanism — findings from completed Cymulate assessments are automatically ingested as Cortex XSOAR incidents on each fetch cycle.

## Additional Information

* Only findings with status **"Not Prevented"** are ingested as incidents.
* The **Fetch category** parameter allows filtering to only **Threat Feed IOC** tagged findings.
* Fetching is cursor-based and resumable: if a large assessment exceeds **Max Fetch** in a single run, the next run continues from exactly where it stopped — no duplicate incidents and no re-processing.
* The integration includes transient error handling for network issues, ensuring stable ingestion even under temporary connectivity problems.
