### GTI Agentic Flow Execution Information
|Execution ID|Flow ID|Status|Duration (Seconds)|Creation Date|Last Modification Date|
|---|---|---|---|---|---|
| [8975c8a7-d574-42c0-8a85-3b3f2e07b53e](https://www.virustotal.com/gui/agentic/flows/execution-log?filter=8975c8a7-d574-42c0-8a85-3b3f2e07b53e) | [11111111-1111-1111-1111-111111111111](https://www.virustotal.com/gui/agentic/flows/11111111-1111-1111-1111-111111111111) | EXECUTION_STATUS_COMPLETED | 0 | 2026-09-28T09:00:00Z | 2026-09-28T09:00:35Z |

### Flow Execution Steps
|Step ID|Node ID|Node Type|Status|Input JSON|Started At|Ended At|Duration (Seconds)|Output|
|---|---|---|---|---|---|---|---|---|
| 8975c8a7-0000-4000-8000-000000000001 | n1 | NODE_TYPE_SCHEDULE_TIME | STEP_STATUS_SUCCESS |  |  | 2026-09-28T09:00:00.396297845Z |  |  |
| 8975c8a7-0000-4000-8000-000000000002 | n2 | NODE_TYPE_RUN_PROMPT | STEP_STATUS_SUCCESS | {"prompt":"Brief about GTI"} | 2026-09-28T09:00:00.414575744Z | 2026-09-28T09:00:33.261625963Z | 33 | Session ID: [63bb000d-67e5-4937-844b-7c04656e7a34](https://www.virustotal.com/gui/agentic/sessions/63bb000d-67e5-4937-844b-7c04656e7a34)<br>See the agent response below. |
| 8975c8a7-0000-4000-8000-000000000003 | n3 | NODE_TYPE_SEND_EMAIL | STEP_STATUS_SUCCESS | {"emails":["soc@example.com"],"flow_name":"Daily malicious-URL digest","source_node_id":"n2","subject":"Daily malicious-URL digest"} | 2026-09-28T09:00:33.327145100Z | 2026-09-28T09:00:34.754639311Z | 1 | dispatched: true |

### Agent Response of Step 8975c8a7-0000-4000-8000-000000000002
### Overview of Google Threat Intelligence

Google Threat Intelligence combines the intelligence of Mandiant, VirusTotal and Google.
