Aggregate entries from multiple sources into AttributionDevice

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
| serial_fields | Comma separated list of fields to treat as serial number. |
| vsys_fields | Comma separate list of field names to be used as vsys. |
| sightings_fields | Comma separated list of field names to be considered sighting counts. |
| source_ip_fields | Comma separated list of field names to be considered as source IPs. |
| internal_ip_networks | Comma separated list of IPv4 Networks to be considered internal \(default to RFC private networks\). |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Expanse.AttributionDevice.serial | Serial Number of the device | string |
| Expanse.AttributionDevice.vsys | VSYS of the device | string |
| Expanse.AttributionDevice.device-group | Device Group inside Panorama | string |
| Expanse.AttributionDevice.xsoar-instance | XSOAR Panorama instance for this device | string |
| Expanse.AttributionDevice.exposing_service | Is the device exposing the asset? | boolean |
| Expanse.AttributionDevice.sightings | Number of sessions seen on this device | number |
