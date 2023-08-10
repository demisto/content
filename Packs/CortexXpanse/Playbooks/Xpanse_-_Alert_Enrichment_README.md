This playbook handles ASM alerts by enriching asset information via integrations with Cloud Service Providers and other IT and Security tools.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Azure - Enrichment
* GCP - Enrichment
* AWS - Enrichment

## Playbook Inputs

---

| **Name**                        | **Description**                                                                                                                                                                                                                                                                      | **Default Value** | **Required** |
|---------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|  | --- |
| Provider                        | The externally detected provider for the alert.                                                                                                                                                                                                                                      | ${incident.xpanseprovider} | Required |
| IP                              | The external IP address associated with the alert.                                                                                                                                                                                                                                   | ${incident.xpanseip} | Required |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Xpanse - Alert Enrichment](../doc_files/Xpanse_-_Alert_Enrichment.png)