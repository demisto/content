Investigates a Cortex XDR incident containing a Cloud Cryptomining related alert. 
The playbook supports AWS, Azure, and GCP and executes the following:

- Cloud enrichment:
   - Collects info about the involved resources
   - Collects info about the involved identities
   - Collects info about the involved IPs
- Verdict decision tree
- Verdict handling:
   - Handle False Positives
   - Handle True Positives
      - Cloud Response - Generic sub-playbook.
- Notifies the SOC if a malicious verdict was found

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Cortex XDR - Cryptomining - Set Verdict
* Cloud Response - Generic
* Cortex XDR - Cloud Enrichment

### Integrations
* CortexXDRIR

### Scripts
* LoadJSON
* IncreaseIncidentSeverity

### Commands
* send-mail
* xdr-get-incident-extra-data
* closeInvestigation
* xdr-update-incident
* xdr-get-cloud-original-alerts
* setIncident

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| incident_id | The incident ID. |  | Optional |
| alert_id | The alert ID. |  | Optional |
| SOCEmailAddress | The SOC email address to use for the alert status notification. | | Optional |
| requireAnalystReview | Whether to require an analyst review after the alert remediation. | True | Optional |
| InternalRange | A list of internal IP ranges to check IP addresses against. | | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cortex XDR - Cloud Cryptomining](../doc_files/Cortex_XDR_-_Cloud_Cryptomining.png)