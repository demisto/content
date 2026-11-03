### Flow execution cancelled successfully.
|Execution ID|Flow ID|Status|Duration (Seconds)|Creation Date|Last Modification Date|
|---|---|---|---|---|---|
| [22222222-2222-2222-2222-222222222222](https://www.virustotal.com/gui/agentic/flows/execution-log?filter=22222222-2222-2222-2222-222222222222) | [11111111-1111-1111-1111-111111111111](https://www.virustotal.com/gui/agentic/flows/11111111-1111-1111-1111-111111111111) | EXECUTION_STATUS_CANCELLED | 0 | 2026-09-28T09:00:00Z | 2026-09-28T09:00:34Z |

### Flow Execution Steps
|Step ID|Node ID|Node Type|Status|Duration (Seconds)|Enqueued At|Started At|Ended At|Expires At|Output|
|---|---|---|---|---|---|---|---|---|---|
| 33333333-3333-3333-3333-333333333331 | n1 | NODE_TYPE_SCHEDULE_TIME | STEP_STATUS_SUCCESS |  |  |  | 2026-09-28T09:00:00.396297845Z |  |  |
| 33333333-3333-3333-3333-333333333332 | n2 | NODE_TYPE_RUN_PROMPT | STEP_STATUS_SUCCESS | 33 | 2026-09-28T09:00:00.336720448Z | 2026-09-28T09:00:00.414575744Z | 2026-09-28T09:00:33.261625963Z | 2026-09-28T09:15:00.414575744Z | Session ID: [44444444-4444-4444-4444-444444444444](https://www.virustotal.com/gui/agentic/sessions/44444444-4444-4444-4444-444444444444)<br>See the agent response below. |
| 33333333-3333-3333-3333-333333333333 | n3 | NODE_TYPE_SEND_EMAIL | STEP_STATUS_SKIPPED |  | 2026-09-28T09:00:33.327145100Z |  |  |  |  |

### Agent Response of Step 33333333-3333-3333-3333-333333333332
Found 12 new malicious URLs.
