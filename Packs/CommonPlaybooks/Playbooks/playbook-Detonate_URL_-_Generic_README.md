This playbook uploads, detonates URLs for supported sandboxes. Currently supported sandboxes are:

* WildFire
* CrowdStrike
* JoeSecurity


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Detonate URL - JoeSecurity
* Detonate URL - CrowdStrike
* Detonate URL - WildFire v2.1

### Integrations

This playbook does not use any integrations.

### Scripts

* IsIntegrationAvailable

### Commands

This playbook does not use any commands.

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | The details of the URL to search for. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| WildFire.Report | The Wildfire findings. | string |
| AttackPattern | The MITRE Attack pattern information. | unknown |
| MITREATTACK | Full MITRE data for the attack pattern. | unknown |
| DBotScore | DBotScore object. | unknown |
| Joe | The sanbox report of the URL analysis | unknown |
| Joe.Submission.most_relevant_analysis | The URL verdict of the sandbox analysis | unknown |
| Joe.Analysis | The sandbox analysis details | unknown |
| csfalconx | The sandbox analysis details | unknown |

## Playbook Image

---

![Detonate URL - Generic](../doc_files/Detonate_URL_-_Generic.png)
