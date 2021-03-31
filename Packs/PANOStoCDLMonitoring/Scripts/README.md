Verify that all firewalls successfully pushed logs to the Cortex Data Lake for the last 12 hours. It's an easy way to do monitoring of the FW connection to CDL.
You can use either a manual list of FW serials or a Panorama integration to get the list of equipment to monitor. 

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | CDL, PAN-OS, XDR |
| Cortex XSOAR Version | 6.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* cdl-query-traffic-logs
* panorama

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| fw_serials | Comma separated list of FW serial numbers to monitor. |
| pan_os_instance_name | PAN-OS integration instance name to retrieve Firewalls serials list. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CDL.monitoring | Monitoring results sorted per Firewall serial. | unknown |
