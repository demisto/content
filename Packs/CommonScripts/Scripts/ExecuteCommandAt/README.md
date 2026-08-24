A wrapper script for the executeCommandAt command to be used in playbooks or the war-room

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incident_ids | The incident ids to run the command on. Can be passed in as CSV format for multiple. |
| command | The command name to run |
| arguments | The arguments to pass into the command. The format should be like: `{"argument_name": "argument_value"}` |

## Outputs

---
There are no outputs for this script.

## Usage Notes

---

### Executing commands on another incident

```war room
// single incident example:
!ExecuteCommandAt command="Print" incident_ids="<incident_id>" arguments=`{"value":"hello world"}`

// multiple incident example:
!ExecuteCommandAt command="Print" incident_ids="<incident_id>,<incident_id>" arguments=`{"value":"hello world"}`
```
