This sub-playbook works with the parent, and will loop over the passed in data, and IF there is a Base64 key, it will decode it, and return a new key called LoopData with contained the original Base64 and the decoded base 64. 

Make sure to check the Playbook Inputs/Outputs to see what to pass in, and what this playbook will output to the parent. 

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* DeleteContext
* SetMultipleValues
* Base64Decode
* Set

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| data | The array of data to pass in.  |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| LoopData | The parsed data with decoded base64. | unknown |

## Playbook Image

---

![XSOAR Engineer Training - For Each Loops (Sub-Playbook)](../doc_files/XSOAR_Engineer_Training_-_For_Each_Loops_(Sub-Playbook).png)
