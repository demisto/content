This Script retrieves all alerts from PANW IoT Cloud, converts them to CEF syslog format and exports them 
to the configured SIEM Server (Syslog Sender)
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | PANW IoT 3rd Party Integration, siem |
| Demisto Version | 6.0.0 |

This Scripts uses the following commands:
'panw-iot-3rd-party-get-asset-list' - For retrieving all alerts from PANW IoT Cloud
'syslog-send' - For sending
This script executes the 'panw-iot-3rd-party-get-asset-list' to retrieve all alerts 

## Used In
---
This script is used in the following playbooks and scripts.
* Bulk Export to SIEM - PANW IoT 3rd Party Integration

## Dependencies
---
This script uses the following commands and scripts.
* panw-iot-3rd-party-report-status-to-panw
* panw-iot-3rd-party-get-asset-list
* syslog-send

## Inputs
---
There are no inputs for this script.

## Outputs
---
There are no outputs for this script.
