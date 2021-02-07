Retrieves all specified assets from the PANW IoT cloud and sends them to the SIEM server.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | PANW IoT 3rd Party Integration, siem |
| Cortex XSOAR Version | 6.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* syslog-send
* panw-iot-3rd-party-get-asset-list
* panw-iot-3rd-party-report-status-to-panw
* panw-iot-3rd-party-convert-assets-to-external-format

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| asset_type | Type of asset. Can be "device", "alert", or "vulnerability". |
| syslog_sender_instance | Name of the configured syslog sender integration instance. |
| panw_iot_3rd_party_instance | Name of the configured PANW Iot 3rd Party integration instance. |

## Outputs
---
There are no outputs for this script.
