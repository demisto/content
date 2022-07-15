This playbook will schedule a specified command and monitor for completion by looking for output in context. Make the playbook context shared globally if you have a command that returns to Context automatically, and you have a specific key to monitor. The key monitored must be a single field value and not an array.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Context Polling - Generic - Single Output
* Context Polling - Generic - Array Output

### Integrations
This playbook does not use any integrations.

### Scripts
* ScheduleCommand

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Command | Command to Schedule | !Print value="The command has executed" | Required |
| Cron | In the format<br/>\* \* \* \* \*<br/>Min Hour Day\(Month\) Month Day\(Week\)<br/><br/>i.e.<br/>1 9 \* \* \*<br/>9:01 AM<br/>- \(server time\) run \!GetTime to see server time |  | Required |
| Number of Times to Run | How many times to run before stopping \(based on cron as well\) |  | Required |
| OutputContextValue | Provide the Key of the value that will be output from the command to poll for completion. If specifying a context value of a command that already outputs to Context set context for sub-playbook to be shared globally. |  | Optional |
| FrequencyToPoll | Frequency to run polling command to check context \(in minutes\) | 1 | Required |
| RegExVal | The regex to check the field for. By default the regex contains .\+, which matches anything other than None. | .+ | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| SchedulingTask.schedResults | Results from command executed | unknown |
