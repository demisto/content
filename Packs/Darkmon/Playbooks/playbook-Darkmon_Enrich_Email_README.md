Sub-playbook that calls the Darkmon !email command and returns DBotScore + Common.Account.Email for the input Email indicator. Designed to be invoked from a parent playbook; does not auto-run on indicator creation.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Darkmon

### Scripts

This playbook does not use any scripts.

### Commands

* email

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Email | The Email indicator value to enrich. Defaults to $\{Email.Address\}. | Email.Address | Required |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore.Indicator | The indicator value. | string |
| DBotScore.Type | The indicator type. | string |
| DBotScore.Vendor | The vendor reporting the score \(Darkmon\). | string |
| DBotScore.Score | The reputation score \(0=Unknown, 1=Good, 2=Suspicious, 3=Bad\). | number |
| DBotScore.Reliability | Source reliability per the Admiralty code. | string |
| Account.Email.Address | The Email value. | string |
| Account.Email.Malicious.Vendor | The vendor that flagged this Email as malicious \(Darkmon\). | string |
| Account.Email.Malicious.Description | Reason this Email was flagged as malicious. | string |
| Darkmon.SearchResult | Full search result records returned by Darkmon for this indicator. | unknown |

## Playbook Image

---

![Darkmon_Enrich_Email](../doc_files/Darkmon_Enrich_Email.png)
