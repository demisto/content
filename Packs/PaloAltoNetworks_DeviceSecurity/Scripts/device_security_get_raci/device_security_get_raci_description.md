## device-security-get-raci Script

This script uses the device and incident attributes to evaluate the Responsible (R) and Informed (I) parties in the RACI model.

A list variable needs to be created with a fixed format JSON. You can create a new Cortex XSOAR list variable under Settings > Advanced > Lists.

By default, the name of the list variable is DEVICE_SECURITY_CONFIG.

There are three main sections in the JSON: devices, alerts, and groups.

**devices** is a list of devices mapped to the owners and delimited by "|". It is based on the device_id, which is a concatenation of the device's category, profile, vendor, and model.
 - device_id: A regular expression to match
 - owner: A group name, which is also defined in the "groups" section.

**alerts** is a list of conditions to map a combination of a Device Security incident type and incident name to the RACI model.
 - device_security_raw_type: Either "Device Security Alert" or "Device Security Vulnerability".
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