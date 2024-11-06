This XSOAR automation script generates a Slack message block to notify users of risks detected by a Data Security Posture Management (DSPM) tool. The Slack block is dynamically constructed based on the details of the security incident and includes options for users to take specific actions, such as creating a Jira ticket or remediating the risk.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| dspmIncident |  |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| slackBlock | Custom Slack for risk details notification. | Unknown |
