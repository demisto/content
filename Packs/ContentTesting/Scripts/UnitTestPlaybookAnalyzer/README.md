Profiles execution time of tasks in a playbook or sub-playbook (if specified).  Provides minimum, maximum, and average task execution times in milliseconds as well as the state of each task: completed, error, notexecuted, started, and waiting.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| playbook | Name of the playbook to analyze. |
| subplaybook | Sub-playbook for analysis versus the parent playbook. |
| firstday | First day to find incident occurrences using the playbook. Example: "2023-03-01". |
| lastday | Last day to find incident occurrences using the playbook: Example: "2023-03-31". |
| maxinc | Maximum number of incidents to analyze. |

## Outputs

---
There are no outputs for this script.
