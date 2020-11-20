This Script retrieves all devices from PANW IoT Cloud, converts them to CEF syslog format and exports them 
to the configured SIEM Server (Syslog Sender)
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | PANW IoT 3rd Party Integration, siem |
| Demisto Version | 6.0.0 |

This Scripts uses the following commands:
'panw-iot-3rd-party-get-asset-list' - For retrieving all devices from PANW IoT Cloud
'syslog-send' - For sending
This script executes the 'panw-iot-3rd-party-get-asset-list' to retrieve all alerts 

## Inputs
---
There are no inputs for this script.

## Outputs
---
There are no outputs for this script.
