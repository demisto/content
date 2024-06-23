This playbook will search a file or process activity of a software by a given image file name using Cortex XDR XQL Engine. The analyst can then choose the files to block.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Cortex XDR - Block File

### Integrations

* XQLQueryingEngine

### Scripts

* DeleteContext
* JsonToTable
* Set

### Commands

* xdr-xql-generic-query

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Filename | File name to search. |  | Optional |
| TimeFrame | Time in relative date or range format \(for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 \+02:00 and 2021-02-01 12:34:56 \+02:00"\). The default is the last 24 hours. |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex XDR - Search And Block Software - XQL Engine](../doc_files/Cortex_XDR_-_Search_And_Block_Software_-_XQL_Engine.png)
