### Flow created successfully.
|Flow ID|Name|Enabled|Nodes|Creation Date|Last Modification Date|
|---|---|---|---|---|---|
| [11111111-1111-1111-1111-111111111111](https://www.virustotal.com/gui/agentic/flows/11111111-1111-1111-1111-111111111111) | Daily malicious-URL digest | true | 3 | 2026-09-10T07:52:49Z | 2026-09-10T07:52:49Z |

### Nodes
|Node ID|Type|Name|Cron Expression|Timezone|Prompt|Reuse Session|Notification Emails|Email Subject|Email Message|
|---|---|---|---|---|---|---|---|---|---|
| n1 | NODE_TYPE_SCHEDULE_TIME | Every morning | 0 9 * * * | UTC |  |  |  |  |  |
| n2 | NODE_TYPE_RUN_PROMPT | Summarise new detections |  |  | Summarise URLs first seen in the last 24h that are flagged malicious by 5+ engines. | false |  |  |  |
| n3 | NODE_TYPE_SEND_EMAIL | Email the SOC |  |  |  |  | soc@example.com | Daily malicious-URL digest | See attached summary. |

### Connections
|Source Node ID|Target Node ID|
|---|---|
| n1 | n2 |
| n2 | n3 |
