This playbook will search a  file or process activity of a software by a given image file name using Microsoft Defender For Endpoint. The analyst can than choose the files he wishes to block.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* MicrosoftDefenderAdvancedThreatProtection

### Scripts

* DeleteContext
* JsonToTable
* Set

### Commands

* microsoft-atp-advanced-hunting
* microsoft-atp-sc-indicator-create

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Filename | File name to search |  | Optional |
| TimeFrame | Time in relative date or range format \(for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 \+02:00 and 2021-02-01 12:34:56 \+02:00"\). The default is the last 24 hours. |  | Optional |
| Defender Indicator Title | The indicator alert title in Defender. | XSOAR Software Block | Optional |
| Indicator Expiration | DateTime string indicating when the indicator expires. Format: \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days\). |  | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![MDE - Search And Block Software](../doc_files/MDE_-_Search_And_Block_Software.png)
