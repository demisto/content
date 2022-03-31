On March 29, 2022, information about a 0-day vulnerability in the popular Java library Spring Core appeared on Twitter.

Spring Framework is an extremely popular framework used by Java developers to build modern applications. If you rely on the Java stack, it is very likely that your development teams use Spring. In some cases, a single specially crafted request is enough to exploit the vulnerability.

Later, it was discovered that these are two separate vulnerabilities, one in Spring Core and the other in Spring Cloud Function:

* RCE in "Spring Core" is a severe vulnerability, aka Spring4Shell.
* RCE in "Spring Cloud Function", aka CVE-2022-22963.

Spring Cloud Function unaffected versions:

* 3.1.7
* 3.2.3


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Rapid Breach Response - Set Incident Info
* Block IP - Generic v3
* Panorama Query Logs
* Search Endpoint by CVE - Generic
* CVE Enrichment - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* http

### Commands
* closeInvestigation
* createNewIndicator

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RelatedCVEs | The vulnerability assigned CVE. | CVE-2022-22963​ | Optional |
| PlaybookDescription | The playbook description. Will be used in the Rapid Breach Response - Set Incident Info sub-playbook. | On March 29, 2022, information about a 0-day vulnerability in the popular Java library Spring Core appeared on Twitter.<br/><br/>Spring Framework is an extremely popular framework used by Java developers to build modern applications. If you rely on the Java stack, it is very likely that your development teams use Spring. In some cases, a single specially crafted request is enough to exploit the vulnerability.<br/><br/>Later, it was discovered that these are two separate vulnerabilities, one in Spring Core and the other in Spring Cloud Function:<br/><br/>* RCE in "Spring Core" is a severe vulnerability, aka Spring4Shell.<br/>* RCE in "Spring Cloud Function", aka CVE-2022-22963.<br/><br/>Spring Cloud Function unaffected versions:<br/><br/>* 3.1.7<br/>* 3.2.3 | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Spring Core and Cloud Function SpEL RCEs](https://raw.githubusercontent.com/demisto/content/82fc619a71e34c599be6c5a75f458abfa2f4c6f2/Packs/SpringRCEs/doc_files/Spring_Core_and_Cloud_Function_SpEL_RCEs.png)