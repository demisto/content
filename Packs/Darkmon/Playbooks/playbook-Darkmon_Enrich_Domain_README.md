Sub-playbook that calls the Darkmon !domain command and returns DBotScore + Common.Domain for the input Domain indicator. Designed to be invoked from a parent playbook; does not auto-run on indicator creation.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Darkmon

### Scripts

This playbook does not use any scripts.

### Commands

* domain

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Domain | The Domain indicator value to enrich. Defaults to $\{Domain.Name\}. | Domain.Name | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The vendor reporting the score \(Darkmon\). | string |
| DBotScore.Score | The reputation score \(0=Unknown, 1=Good, 2=Suspicious, 3=Bad\). | number |
| DBotScore.Reliability | Source reliability per the Admiralty code. | string |
| Domain.Name | The Domain value. | string |
| Domain.Malicious.Vendor | The vendor that flagged this Domain as malicious \(Darkmon\). | string |
| Domain.Malicious.Description | Reason this Domain was flagged as malicious. | string |
| Darkmon.SearchResult | Full search result records returned by Darkmon for this indicator. | unknown |

## Playbook Image

---

![Darkmon - Enrich Domain](../doc_files/Darkmon_-_Enrich_Domain.png)
