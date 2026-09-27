Calculates the responsible and informed parties for a Device Security incident by matching incident and device details against the Device Security configuration list.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | device security |
| Cortex XSOAR Version | 6.10.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* PANW Device Security Incident Handling with ServiceNow

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incident_name | The name of the Device Security incident. |
| raw_type | The raw type of the incident. |
| category | The device category. |
| profile | The device profile. |
| vendor | The device vendor. |
| model | The device model. |
| device_security_config_list_name | The name of the list containing the Device Security configuration. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksDeviceSecurity.RACI.Model | The RACI model of the Device Security incident. | object |
| PaloAltoNetworksDeviceSecurity.RACI.Model.r | The responsible party in the RACI model. | string |
| PaloAltoNetworksDeviceSecurity.RACI.Model.r_email | The email address of the responsible party in the RACI model. | string |
| PaloAltoNetworksDeviceSecurity.RACI.Model.i | The informed parties in the RACI model. | string |
| PaloAltoNetworksDeviceSecurity.RACI.Model.i_email | The comma-separated email addresses of the informed parties in the RACI model. | string |
| PaloAltoNetworksDeviceSecurity.RACI.Model.owner | The Device Security owner of the device. | string |
| PaloAltoNetworksDeviceSecurity.RACI.Model.r_snow | The ServiceNow information for the responsible party. | object |
| PaloAltoNetworksDeviceSecurity.RACI.Model.r_snow.fields | The fields of the ServiceNow ticket. | string |
| PaloAltoNetworksDeviceSecurity.RACI.Model.r_snow.custom_fields | The custom fields of the ServiceNow ticket. | string |
| PaloAltoNetworksDeviceSecurity.RACI.Model.r_snow.table | The table of the ServiceNow ticket. | string |
