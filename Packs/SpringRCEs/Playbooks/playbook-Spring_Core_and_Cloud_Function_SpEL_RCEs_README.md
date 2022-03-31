On March 29, 2022, information about a 0-day vulnerability in the popular Java library Spring Core appeared on Twitter.

Spring Framework is an extremely popular framework used by Java developers to build modern applications. If you rely on the Java stack, it is very likely that your development teams use Spring. In some cases, a single specially crafted request is enough to exploit the vulnerability.

Later, it was discovered that these are two separate vulnerabilities, one in Spring Core and the other in Spring Cloud Function:

* RCE in "Spring Core" is a severe vulnerability, aka Spring4Shell.
* RCE in "Spring Cloud Function", aka CVE-2022-22963.

Spring Cloud Function unaffected versions:

* 3.1.7
* 3.2.3

Note: you can execute this playbook using the Incidents view by creating a new incident or by using a dedicated job to schedule the playbook execution.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block IP - Generic v3
* CVE Enrichment - Generic v2
* Panorama Query Logs
* Rapid Breach Response - Set Incident Info
* Search Endpoint by CVE - Generic

### Integrations
This playbook does not use any integrations.

### Scripts
* http

### Commands
* createNewIndicator
* closeInvestigation

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RelatedCVEs | The vulnerability assigned CVE. | CVE-2022-22963​ | Optional |
| PlaybookDescription | The playbook description. Will be used in the Rapid Breach Response - Set Incident Info sub-playbook. | On March 29, 2022, information about a 0-day vulnerability in the popular Java library Spring Core appeared on Twitter.<br/><br/>Spring Framework is an extremely popular framework used by Java developers to build modern applications. If you rely on the Java stack, it is very likely that your development teams use Spring. In some cases, a single specially crafted request is enough to exploit the vulnerability.<br/><br/>Later, it was discovered that these are two separate vulnerabilities, one in Spring Core and the other in Spring Cloud Function:<br/><br/>* RCE in "Spring Core" is a severe vulnerability, aka Spring4Shell.<br/>* RCE in "Spring Cloud Function", aka CVE-2022-22963.<br/><br/>Spring Cloud Function unaffected versions:<br/><br/>* 3.1.7<br/>* 3.2.3 | Optional |
| AutoCloseIncident | Whether to close the incident automatically or continue with manual investigation. | true | Optional |
| BlockIndicatorsAutomatically | Whether to block the indicators automatically. | true | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Spring Core and Cloud Function SpEL RCEs](https://raw.githubusercontent.com/demisto/content/4df6e954d7f725c577ac37fc5aa070e3851d2015/Packs/SpringRCEs/doc_files/Spring_Core_and_Cloud_Function_SpEL_RCEs.png)