Sub-playbook that calls the Darkmon !file command and returns DBotScore + Common.File for the input File indicator. Designed to be invoked from a parent playbook; does not auto-run on indicator creation.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Darkmon

### Scripts

This playbook does not use any scripts.

### Commands

* file

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | The File indicator value to enrich. Defaults to $\{File.MD5\}. | File.MD5 | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The vendor reporting the score \(Darkmon\). | string |
| DBotScore.Score | The reputation score \(0=Unknown, 1=Good, 2=Suspicious, 3=Bad\). | number |
| DBotScore.Reliability | Source reliability per the Admiralty code. | string |
| File.MD5 | The File value. | string |
| File.Malicious.Vendor | The vendor that flagged this File as malicious \(Darkmon\). | string |
| File.Malicious.Description | Reason this File was flagged as malicious. | string |
| Darkmon.SearchResult | Full search result records returned by Darkmon for this indicator. | unknown |
