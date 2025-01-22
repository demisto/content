Intel 471's watcher alerts provide a mechanism by which customers can be notified in a timely manner of Titan content that is most relevant to them.
## Configure Intel471 Watcher Alerts in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetches incidents |  | False |
| Username | Titan username | False |
| Password | Titan API key | False |
| Maximum number of incidents per fetch |  | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Incidents Fetch Interval |  | False |
| Severity | The severity to apply to incidents | True |
| Watcher group UID(s) | The UID(s) of the watcher group(s) for which alerts should be fetched | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | How far back in time to go when performing the first fetch. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## Fetched Incidents Data
---
Returns the Intel 471 Watcher Alerts. Creates incidents in Cortex XSOAR and populate the incident `details` field 
with the alert content.