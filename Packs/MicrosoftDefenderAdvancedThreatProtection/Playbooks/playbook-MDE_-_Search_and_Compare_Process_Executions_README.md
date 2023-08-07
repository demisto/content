This playbook is a generic playbook that receives process name and command-line argument, and uses "Microsoft Defender For Endpoint" integration to search for the given process executions and compare the command-line argument from the results to the command-line argument received from the playbook input.

Notice - under the input "Processes", the playbook should receive an array that contains the following keys:
- value: *process name*
-commands: *command-line arguments*

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* MicrosoftDefenderAdvancedThreatProtection

### Scripts

* DeleteContext
* StringSimilarity
* Set

### Commands

* microsoft-atp-advanced-hunting

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Processes |  |  | Optional |
| HuntingTimeFrame | Time in relative date or range format \(for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 \+02:00 and 2021-02-01 12:34:56 \+02:00"\). The default is the last 24 hours. | 7 days | Optional |
| StringSimilarityThreshold | StringSimilarity automation threshold: A number between 0 and 1, where 1 represents the most similar results of string comparisons. The automation will output only the results with a similarity score equal to or greater than the specified threshold. | 0.5 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| StringSimilarity | StringSimilarity results. | unknown |
| Findings | Suspicious process executions found. | unknown |

## Playbook Image

---

![MDE - Search and Compare Process Executions](../doc_files/MDE_-_Search_and_Compare_Process_Executions.png)
