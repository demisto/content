---

## Cloud Token Theft Response Playbook

The **Cloud Token Theft Response Playbook** provides a structured and comprehensive flow to effectively respond to and mitigate alerts involving the theft of cloud tokens. The playbook supports AWS, GCP, and Azure and executes the following:

**Cloud Enrichment:**
- Enriches the involved resources.
- Enriches the involved identities.
- Enriches the involved IPs.

**Verdict Decision Tree:**
- Determines the appropriate verdict based on the investigation findings.

**Early Containment using the Cloud Response - Generic Playbook:**
- Implements early containment measures to prevent further impact.

**Cloud Persistence Threat Hunting:**
- Conducts threat hunting activities to identify any cloud persistence techniques.

**Enriching and Responding to Hunting Findings:**
- Performs additional enrichment and responds to the findings from threat hunting.

**Verdict Handling:**
- Handles false positives identified during the investigation.
- Handles true positives by initiating appropriate response actions.

### Supported Alerts

| Alert Name                                          | CSP   |
|----------------------------------------------------|-------|
| Suspicious usage of AWS Lambda’s token              | AWS   |
| Suspicious usage of AWS Lambda’s role               | AWS   |
| Suspicious usage of EC2 token                       | AWS   |
| Remote usage of an AWS service token                | AWS   |
| Remote usage of an AWS EKS token                    | AWS   |
| Suspicious usage of an AWS EKS token                | AWS   |
| Suspicious usage of an AWS ECS token                | AWS   |
| Remote usage of an AWS ECS token                    | AWS   |
| Suspicious usage of AWS service token               | AWS   |
| Remote usage of an App engine Service Account token | GCP   |
| Suspicious usage of App engine Service Account token| GCP   |
| Remote usage of VM Service Account token            | GCP   |
| Suspicious usage of VM Service Account toke         | GCP   |

---

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* IP Enrichment - Generic v2
* Cloud Threat Hunting - Persistence
* Cortex XDR - XCloud Token Theft - Set Verdict
* TIM - Indicator Relationships Analysis
* Entity Enrichment - Generic v3
* Cloud Enrichment - Generic
* Cloud Response - Generic

### Integrations

This playbook does not use any integrations.

### Scripts

* ParseHTMLIndicators
* LoadJSON

### Commands

* xdr-get-cloud-original-alerts
* xdr-update-incident
* setIncident
* closeInvestigation

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| alert_id | The alert ID. | alert.investigationId | Optional |
| InternalRange | A comma-separated list of internal IP ranges to check IP addresses against. The list should be provided in CIDR notation. |  | Optional |
| ResolveIP | Determines whether to convert the IP address to a hostname using a DNS query \(True/ False\). | False | Optional |
| earlyContainment | Whether to execute early containment.<br/>This action allows you to respond rapidly but have higher probability for false positives. | True | Optional |
| VPNIPList | This input can process two types of data:<br/>1. A comma-separated list of internal IPs assigned by the VPN provider using a XSIAM list or an hardcoded array.<br/>2. A link to an IP list which will be processed and extract the IP dynamically which each execution.<br/><br/>For CIDRs, use the InternalRange input. |  | Optional |
| autoResourceRemediation | Whether to execute the resource remediation automatically. | False | Optional |
| autoAccessKeyRemediation | Whether to execute the access key remediation automatically. | False | Optional |
| autoUserRemediation | Whether to execute the user remediation automatically. | False | Optional |
| autoBlockIndicators | Whether to execute the indicators remediation automatically. | False | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Cortex XDR - XCloud Token Theft Response](../doc_files/Cortex_XDR_-_XCloud_Token_Theft_Response.png)
