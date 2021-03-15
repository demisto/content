Verify that all firewalls successfully pushed logs to the Cortex Data Lake for the last 12 hours. It's an easy way to do monitoring of the FW connection to CDL.
You can use either a manual list of FW serials or a Panorama integration to get the list of equipment to monitor. 

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | CDL, Panw, xdr |

## Dependencies
---
This script uses the following commands and scripts.
* panorama
* cdl-query-traffic-logs

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| fw_serials | Comma separated list of FW serial numbers to monitor. |
| panorama | Panorama integration name to retrieve FW list |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| monitoring_result | Monitoring results sorted per FW serial | unknown |
