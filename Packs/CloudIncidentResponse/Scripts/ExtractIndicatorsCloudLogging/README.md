This script will extract indicators from a given AWS CloudTrail or GCP Logging event.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.8.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| json_data | The event JSON or data. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CloudIndicators.arn | The ARN extracted from the event | Unknown |
| CloudIndicators.access_key_id | The access key ID extracted from the event | Unknown |
| CloudIndicators.resource_name | The resource name extracted from the event | Unknown |
| CloudIndicators.source_ip | The source ip extracted from the event | Unknown |
| CloudIndicators.username | The username extracted from the event | Unknown |
| CloudIndicators.event_name | The event name extracted from the event | Unknown |
| CloudIndicators.user_agent | The user agent extracted from the event | Unknown |
