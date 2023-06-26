The script accepts indicators as input and creates an indicator query in the relevant Palo Alto Networks products.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Panw |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| ip | A commma-separated list of IP addresses for which to create the query. |
| hash | A commma-separated list of file hashes for which to create the query. |
| domain | A commma-separated list of domains for which to create the query. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Query.IP.CortexTrapsIP | The query for the specified IP address indicators. This query is relevant for the Cortex Traps table "tms.threat", which is the agent IP. | String |
| Query.IP.CortexAnalyticsIP | The query for the specified IP address indicators. This query is relevant for the Cortex Analytics table "tms.analytics", which is the agent IP. | String |
| Query.IP.CortexTrafficIP | The query for the specified IP address indicators. This query is relevant for the Cortex Traffic table "panw.traffic", and includes both source and destination. | String |
| Query.IP.CortexThreatIP | The query for the specified IP address indicators. This query is relevant for the Cortex Threat table "panw.threat", and includes both source and destination. | String |
| Query.IP.AutofocusSessionsIP | The query \(in JSON format\) for the specified IP address indicators. This query is relevant for AutoFocus, includes both source and destination. | String |
| Query.IP.PanoramaIP | The query \(in Panorama syntax\) for the specified IP address indicators. This query is relevant for Panorama, and is valid for all log types. | String |
| Query.Hash.CortexTrapsHash | The query for the specified file hash indicators. This query is relevant for the Cortex Traps table "tms.threat", which contains only SHA256 hashes. | String |
| Query.Hash.CortexAnalyticsHash | The query for the specified file hash indicators. This query is relevant for the Cortex Analytics table "tms.analytics", which contains only SHA256 hashes. | String |
| Query.Hash.CortexThreatHash | The query for the specified file hash indicators. This query is relevant for the Cortex Threat table "panw.threat", which contains only SHA256 hashes. | String |
| Query.Hash.AutofocusSessionsHash | The query \(in JSON format\) for the specified file hash indicators. This query is relevant for AutoFocus, and supports the following file hashes: MD5, SHA1, and SHA256. | String |
| Query.Hash.PanoramaHash | The query \(in Panorama syntax\) for the specified file hash indicators. This query is relevant for the WildFire log in Panorama, and only supports SHA256 hashes. | String |
| Query.Domain.CortexThreatDomain | The query for the domain indicators. This query is relevant for the Cortex Threat table "panw.threat". | String |
| Query.Domain.AutofocusSessionsDomain | The query \(in JSON format\) for the domain indicators. This query is relevant for AutoFocus. | String |
| Query.Domain.PanoramaDomain | The query \(in Panorama syntax\) for the domain indicators. This query is relevant for Panorama. | String |
