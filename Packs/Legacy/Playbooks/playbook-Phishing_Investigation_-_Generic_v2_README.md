Use this playbook to investigate and remediate a potential phishing incident. The playbook simultaneously engages with the user that triggered the incident, while investigating the incident itself.

The final remediation tasks are always decided by a human analyst.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Extract Indicators From File - Generic v2
* Domain Enrichment - Generic v2
* URL Enrichment - Generic v2
* Block Indicators - Generic v2
* Search And Delete Emails - Generic
* Calculate Severity - Generic v2
* Process Email - Generic
* File Enrichment - Generic v2
* Detonate File - Generic
* IP Enrichment - External - Generic v2
* Email Address Enrichment - Generic v2.1

### Integrations
* Builtin

### Scripts
* DBotPredictPhishingWords
* AssignAnalystToIncident
* SendEmail
* CheckEmailAuthenticity
* Set

### Commands
* setIncident
* send-mail
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| Role | The default role to assign the incident to. | Administrator |  | Required |
| SearchAndDelete | Enable the &quot;Search and Delete&quot; capability \(can be either &quot;True&quot; or &quot;False&quot;\).
In case of a malicious email, the &quot;Search and Delete&quot; sub\-playbook will look for other instances of the email and delete them pending analyst approval. | False |  | Optional |
| BlockIndicators | Enable the &quot;Block Indicators&quot; capability \(can be either &quot;True&quot; or &quot;False&quot;\).
In case of a malicious email, the &quot;Block Indicators&quot; sub\-playbook will block all malicious indicators in the relevant integrations. | False |  | Optional |
| AuthenticateEmail | Whether the authenticity of the email should be verified, using SPF, DKIM and DMARC. | False |  | Optional |
| OnCall | Set to true to assign only user that is currently on shift. Requires Cortex XSOAR v5.5 or later. | false |  | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.


## Playbook Image
---
![Phishing_Investigation_Generic_v2](https://raw.githubusercontent.com/demisto/content/master/docs/images/playbooks/Phishing_Investigation_Generic_v2.png)
