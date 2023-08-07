This playbook will search a  file or process activity of a software by a given image file name. The analyst can than choose the files he wishes to block.
The following integrations is supported:

- Cortex XDR XQL Engine 
- Microsoft Defender For Endpoint

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* e5a31f4b-d3bb-4ba5-8fa3-a95105a3c5e4
* d4b0f0de-7c11-4050-8e01-9067112f2772

### Integrations

This playbook does not use any integrations.

### Scripts

This playbook does not use any scripts.

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| FileName | File name to search |  | Optional |
| TimeFrame | Time in relative date or range format \(for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 \+02:00 and 2021-02-01 12:34:56 \+02:00"\). The default is the last 24 hours. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Search And Block Software - Generic](../doc_files/Search_And_Block_Software_-_Generic.png)
