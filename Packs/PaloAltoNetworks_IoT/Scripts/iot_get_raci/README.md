IoT RACI model script
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | iot |
| Cortex XSOAR Version | 5.5.0 |

This script is using the device and incident attributes to evaluate the Responsible (R) and Informed (I) parties in the RACI model.

A list variable needs to be created with a fixed format JSON. You can create a new XSOAR list variable under Settings > Advanced > Lists.

By default, the name of the list variable is IOT_CONFIG.

There are three main sections in the JSON: devices, alerts, and groups.

"devices" is a list of devices mapping to the owners based on the device_id, which is a concatenation of the device's category, profile, vendor and model delimited by "|".
 - device_id: a regular expression to match
 - owner: a group name, which is also defined in the "groups" section

"alerts" is a list of conditions to map a combination of IoT incident type and incident names to the RACI model.
 - iot_raw_type: either "IoT Alert" or "IoT Vulnerability"
 - name_regex: a list of regular expressions trying to match with the alert/vulnerability names
 - raci: a section to define the RACI model for the match. If the value is "IOT_OWNER", we look up the underlying group using the mapping in "devices" section.

"groups" is all the groups found in the "devices" and "alerts" section.
 - email: the email of the group, this is used when setting the incident owner in XSOAR or sending an email through the email integration
 - snow: it has three fields, table, fields and custom_fields. Those are the fields when you use the official ServiceNow integration when you create a ServiceNow ticket.

Here is the template of the JSON:

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
            "iot_raw_type": "IoT Alert",
            "name_regex": [
                "DOUBLEPULSAR.+",
                "ECLIPSEDWING.+",
                "ETERNALBLUE.+"
            ],
            "raci": {
                "r": "SOC",
                "i": ["IOT_OWNER"]
            }
        },
        {
            "iot_raw_type": "IoT Vulnerability",
            "raci": {
                "r": "IOT_OWNER",
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
* PANW IoT Incident Handling with ServiceNow

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| alert_name | The name of the IoT alert. |
| raw_type | The raw type of the incident. |
| category | The device category. |
| profile | The device profile. |
| vendor | The device vendor. |
| model | The device model. |
| iot_config_list_name | The variable name for IOT\_CONFIG. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PaloAltoNetworksIoT.RACI | The RACI model of the IoT incident | unknown |
| PaloAltoNetworksIoT.RACI.r | The responsible in the RACI model | string |
| PaloAltoNetworksIoT.RACI.r_email | The email of responsible in the RACI model | string |
| PaloAltoNetworksIoT.RACI.i | The informed in the RACI model | string |
| PaloAltoNetworksIoT.RACI.i_email | The emails of informed in the RACI model delimited by comma | string |
| PaloAltoNetworksIoT.RACI.owner | The IoT owner of the device | string |
| PaloAltoNetworksIoT.RACI.r_snow | The ServiceNow information of the incident responsible | string |
| PaloAltoNetworksIoT.RACI.r_snow.fields | The fields of the ServiceNow ticket | string |
| PaloAltoNetworksIoT.RACI.r_snow.custom_fields | The custom fields of the ServiceNow ticket | string |
| PaloAltoNetworksIoT.RACI.r_snow.table | The table of the ServiceNow ticket | string |
