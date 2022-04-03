On March 29, 2022, information about a 0-day vulnerability in the popular Java library Spring Core appeared on Twitter.

Spring Framework is an extremely popular framework used by Java developers to build modern applications. If you rely on the Java stack, it is very likely that your development teams use Spring. In some cases, a single specially crafted request is enough to exploit the vulnerability.

Later, it was discovered that these are two separate vulnerabilities, one in Spring Core and the other in Spring Cloud Function:

**CVE-2022-22965 - RCE in "Spring Core" is a severe vulnerability, aka Spring4Shell.**

**CVE-2022-22963 - RCE in "Spring Cloud Function SpEL".**

**Spring Core vulnerability requirements:**

* JDK 9 or higher
* Apache Tomcat as the Servlet container
* Packaged as WAR
* spring-webmvc or spring-webflux dependency
* Spring Framework versions 5.3.0 to 5.3.17, 5.2.0 to 5.2.19, and older versions

**Spring Cloud Function unaffected versions:**

* 3.1.7
* 3.2.3

**Note:** You can execute this playbook using the Incidents view by creating a new incident or by using a dedicated job to schedule the playbook execution.

**Additional resources:**

[Spring Framework RCE](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)

[CVE-2022-22965: Spring Core Remote Code Execution Vulnerability Exploited In the Wild
](https://unit42.paloaltonetworks.com/cve-2022-22965-springshell/)

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Block IP - Generic v3
* Search Endpoint by CVE - Generic
* Panorama Query Logs
* Rapid Breach Response - Set Incident Info
* CVE Enrichment - Generic v2

### Integrations
This playbook does not use any integrations.

### Scripts
* http

### Commands
* redlock-get-rql-response
* closeInvestigation
* createNewIndicator

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RelatedCVEs | The vulnerability assigned CVE. | CVE-2022-22963,CVE-2022-22965 | Optional |
| PlaybookDescription | The playbook description. Will be used in the Rapid Breach Response - Set Incident Info sub-playbook. | On March 29, 2022, information about a 0-day vulnerability in the popular Java library Spring Core appeared on Twitter.<br/><br/>Spring Framework is an extremely popular framework used by Java developers to build modern applications. If you rely on the Java stack, it is very likely that your development teams use Spring. In some cases, a single specially crafted request is enough to exploit the vulnerability.<br/><br/>Later, it was discovered that these are two separate vulnerabilities, one in Spring Core and the other in Spring Cloud Function:<br/><br/>**CVE-2022-22965 - RCE in "Spring Core" is a severe vulnerability, aka Spring4Shell.**<br/><br/>**CVE-2022-22963 - RCE in "Spring Cloud Function SpEL".**<br/><br/>**Spring Core vulnerability requirements:**<br/><br/>* JDK 9 or higher<br/>* Apache Tomcat as the Servlet container<br/>* Packaged as WAR<br/>* spring-webmvc or spring-webflux dependency<br/>* Spring Framework versions 5.3.0 to 5.3.17, 5.2.0 to 5.2.19, and older versions<br/><br/>**Spring Cloud Function unaffected versions:**<br/><br/>* 3.1.7<br/>* 3.2.3<br/><br/>**Note:** You can execute this playbook using the Incidents view by creating a new incident or by using a dedicated job to schedule the playbook execution. | Optional |
| AutoCloseIncident | Whether to close the incident automatically or continue with manual investigation. | true | Optional |
| BlockIndicatorsAutomatically | Whether to block the indicators automatically. | true | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Spring Core and Cloud Function SpEL RCEs](https://raw.githubusercontent.com/demisto/content/7b75e7e91ed9878cf37a93ac81cac13b94e26b20/Packs/SpringRCEs/doc_files/Spring_Core_and_Cloud_Function_SpEL_RCEs.png)