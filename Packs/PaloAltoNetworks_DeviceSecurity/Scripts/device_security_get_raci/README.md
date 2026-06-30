Device Security RACI model script

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | device security |
| Cortex XSOAR Version | 5.5.0 |

This script uses the device and incident attributes to evaluate the Responsible (R) and Informed (I) parties in the RACI model.

A list variable needs to be created with a fixed format JSON. You can create a new Cortex XSOAR list variable under Settings > Advanced > Lists.

By default, the name of the list variable is DEVICE_SECURITY_CONFIG.

There are three main sections in the JSON: devices, alerts, and groups.

**devices** is a list of devices mapped to the owners and delimited by "|". It is based on the device_id, which is a concatenation of the device's category, profile, vendor, and model.

- device_id: A regular expression to match
- owner: A group name, which is also defined in the "groups" section.

**alerts** is a list of conditions to map a combination of a Device Security incident type and incident name to the RACI model.

- device_security_raw_type: Either "Device Security Alert" or "Device Security Vulnerability"
- name_regex: A list of regular expressions to match with the alert/vulnerability names.
- raci: A section to define the RACI model for the match. If the value is "DEVICE_SECURITY_OWNER", the system looks up the underlying group using the mapping in the **devices** section.

**groups** is all the groups found in the **devices** and **alerts** sections.

- email: The email of the group. This is used when setting the incident owner in Cortex XSOAR or sending an email through the email integration.
- snow: Contains three fields: table, fields, and custom_fields. These fields are used when creating a ticket using the ServiceNow integration.

The following is the JSON template:

```json
{
    "devices": [
        {
            "device_id": "Audio Streaming|Profusion.*",
            "owner": "IT_AUDIO_VIDEO"
        },
        {
            "device_id": "Camera|Avigilon Camera.*",
            "owner": "PHYSICAL_SECURITY"
        }
    ],
    "alerts": [
        {
            "device_security_raw_type": "Device Security Alert",
            "name_regex": [
                "DOUBLEPULSAR.+",
                "ECLIPSEDWING.+",
                "ETERNALBLUE.+"
            ],
            "raci": {
                "r": "SOC",
                "i": ["DEVICE_SECURITY_OWNER"]
            }
        },
        {
            "device_security_raw_type": "Device Security Vulnerability",
            "raci": {
                "r": "DEVICE_SECURITY_OWNER",
                "i": ["INFOSEC", "SOC"]
            }
        }
    ],
    "groups": {
        "DEFAULT": {
            "email": "default@example.com"
        },
        "SOC": {
            "email": "soc@example.com"
        },
        "INFOSEC": {
            "email": "infosec@example.com"
        },
        "IT_AUDIO_VIDEO": {
            "email": "av@example.com",
            "snow": {
                "table": "incident",
                "fields": {
                    "assignment_group": "98dae8874fd67348bf547fe24210c7a0"
                },
                "custom_fields": {
                    "u_custom_field1": "IT",
                    "u_category": "05b9e5371b3b08905f28fc43cd4bcbe2"
                }
            }
        },
        "PHYSICAL_SECURITY": {
            "email": "security@example.com"
        }
    }
}
```

## Used In

---
This script is used in the following playbooks and scripts.

- PANW Device Security Incident Handling with ServiceNow

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
| device_security_config_list_name | The variable name for DEVICE_SECURITY\_CONFIG. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksDeviceSecurity.RACI | The RACI model of the DeviceSecurity incident. | unknown |
| PaloAltoNetworksDeviceSecurity.RACI.r | The responsible party in the RACI model. | string |
| PaloAltoNetworksDeviceSecurity.RACI.r_email | The email of the responsible party in the RACI model | string |
| PaloAltoNetworksDeviceSecurity.RACI.i | The informed party in the RACI model. | string |
| PaloAltoNetworksDeviceSecurity.RACI.i_email | A comma-separated list of the informed party emails in the RACI model. | string |
| PaloAltoNetworksDeviceSecurity.RACI.owner | The DeviceSecurity owner of the devices | string |
| PaloAltoNetworksDeviceSecurity.RACI.r_snow | The ServiceNow information of the incident responsible party. | string |
| PaloAltoNetworksDeviceSecurity.RACI.r_snow.fields | The fields of the ServiceNow ticket | string |
| PaloAltoNetworksDeviceSecurity.RACI.r_snow.custom_fields | The custom fields of the ServiceNow ticket. | string |
| PaloAltoNetworksDeviceSecurity.RACI.r_snow.table | The table of the ServiceNow ticket. | string |
