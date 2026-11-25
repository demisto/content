This pack is a test pack for the AgentiX Job Center content item.

## What does this pack do?

This pack is intended for Cortex Agentic AI.

It contains sample Job Center jobs that run an agent against cases, either once or on a recurring interval.

## Jobs

| Job | Trigger | Schedule | Queue policy | Status |
| --- | --- | --- | --- | --- |
| Case Followup | Interval | Every 30 minutes, 6 runs | skip | Enabled |
| Case Daily Summary (v1) | One time | - | - | Enabled |
| Case_Escalation-Check [beta] | Interval | Every 10 minutes, 12 runs | cancel_prev | Disabled |
| Case Hourly Monitor | Interval | Every 120 minutes, 1 run | concurrent | Enabled |

**Note:** The agent and prompt IDs used by these jobs (for example, `case-investigation-agent` and `case-followup-prompt`) are placeholders and do not refer to real agents.
