Aggregate entries from multiple sources into AttributionIP

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | |
| Demisto Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Expanse Attribution Subplaybook

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | Input list. |
| current | Current aggregation state. |
| source_ip_fields | Comma separated list of fields to treat as source IPs. |
| internal_ip_networks | Comma separated list of IPv4 Networks to be considered internal \(default to RFC private networks\). |
| sightings_fields | Comma separated list of field names to be considered sighting counts. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Expanse.AttributionIP.ip | IP address | string |
| Expanse.AttributionIP.private | Is the IP private? | boolean |
| Expanse.AttributionIP.sightings | Number of sessions seen on this device | number |
