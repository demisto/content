Sub-playbook that calls the Darkmon !url command and returns DBotScore + Common.URL for the input URL indicator. Designed to be invoked from a parent playbook; does not auto-run on indicator creation.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Darkmon

### Scripts

This playbook does not use any scripts.

### Commands

* url

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | The URL indicator value to enrich. Defaults to $\{URL.Data\}. | URL.Data | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The vendor reporting the score \(Darkmon\). | string |
| DBotScore.Score | The reputation score \(0=Unknown, 1=Good, 2=Suspicious, 3=Bad\). | number |
| DBotScore.Reliability | Source reliability per the Admiralty code. | string |
| URL.Data | The URL value. | string |
| URL.Malicious.Vendor | The vendor that flagged this URL as malicious \(Darkmon\). | string |
| URL.Malicious.Description | Reason this URL was flagged as malicious. | string |
| Darkmon.SearchResult | Full search result records returned by Darkmon for this indicator. | unknown |

## Playbook Image

---

![Darkmon - Enrich URL](../doc_files/Darkmon_-_Enrich_URL.png)
