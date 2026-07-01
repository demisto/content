Device Security RACI model script.

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
| device_security_config_list_name | The variable name for DEVICE_SECURITY_CONFIG. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksDeviceSecurity.RACI | The RACI model of the Device Security incident. | unknown |
