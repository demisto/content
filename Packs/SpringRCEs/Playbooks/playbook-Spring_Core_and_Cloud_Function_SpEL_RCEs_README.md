On March 29, 2022, information about a 0-day vulnerability in the popular Java library Spring Core appeared on Twitter.

Spring Framework is an extremely popular framework used by Java developers to build modern applications. If you rely on the Java stack, it is very likely that your development teams use Spring. In some cases, a single specially crafted request is enough to exploit the vulnerability.

Later, it was discovered that these are two separate vulnerabilities, one in Spring Core and the other in Spring Cloud Function:

**CVE-2022-22965 - RCE in "Spring Core" is a severe vulnerability, aka Spring4Shell**

**CVE-2022-22963 - RCE in "Spring Cloud Function SpEL"**

**CVE-2022-22947 - RCE in "Spring Cloud Gateway"**

**Spring Core vulnerability requirements:**

* JDK 9 or higher
* Apache Tomcat as the Servlet container
* Packaged as WAR
* spring-webmvc or spring-webflux dependency
* Spring Framework versions 5.3.0 to 5.3.17, 5.2.0 to 5.2.19, and older versions

**Spring Cloud Function unaffected versions:**

* 3.1.7
* 3.2.3

**This playbook will provide you with a first response kit which includes:**

* Hunting
    * Panorama
    * Prisma Cloud Compute
    * XDR XQL queries - set the playbook input **RunXQLHuntingQueries** to 'True' if you would like the XQL to be executed via the playbook.
    * XDR Alerts - Search for new incidents including one or more of Spring RCEs dedicated Cortex XDR signatures
* Remediation
* Mitigations

**Note:** You can execute this playbook using the Incidents view by creating a new incident or by using a dedicated job to schedule the playbook execution.

**Additional resources:**

[Spring Framework RCE](https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement)

[CVE-2022-22965: Spring Core Remote Code Execution Vulnerability Exploited In the Wild
](https://unit42.paloaltonetworks.com/cve-2022-22965-springshell/)


## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* CVE Enrichment - Generic v2
* Block IP - Generic v3
* Panorama Query Logs
* Search Endpoint by CVE - Generic
* Rapid Breach Response - Set Incident Info

### Integrations

This playbook does not use any integrations.

### Scripts

* http
* IsIntegrationAvailable
* SearchIncidentsV2

### Commands

* xdr-xql-generic-query
* createNewIndicator
* prisma-cloud-config-search
* closeInvestigation
* redlock-get-rql-response

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RelatedCVEs | The vulnerability assigned CVE. | CVE-2022-22963,CVE-2022-22965,cve-2022-22947 | Optional |
| PlaybookDescription | The playbook description. Will be used in the Rapid Breach Response - Set Incident Info sub-playbook. | On March 29, 2022, information about a 0-day vulnerability in the popular Java library Spring Core appeared on Twitter.<br/><br/>Spring Framework is an extremely popular framework used by Java developers to build modern applications. If you rely on the Java stack, it is very likely that your development teams use Spring. In some cases, a single specially crafted request is enough to exploit the vulnerability.<br/><br/>Later, it was discovered that these are two separate vulnerabilities, one in Spring Core and the other in Spring Cloud Function:<br/><br/>**CVE-2022-22965 - RCE in "Spring Core" is a severe vulnerability, aka Spring4Shell**<br/><br/>**CVE-2022-22963 - RCE in "Spring Cloud Function SpEL"**<br/><br/>**CVE-2022-22947 - RCE in "Spring Cloud Gateway"**<br/><br/>**Spring Core vulnerability requirements:**<br/><br/>* JDK 9 or higher<br/>* Apache Tomcat as the Servlet container<br/>* Packaged as WAR<br/>* spring-webmvc or spring-webflux dependency<br/>* Spring Framework versions 5.3.0 to 5.3.17, 5.2.0 to 5.2.19, and older versions<br/><br/>**Spring Cloud Function unaffected versions:**<br/><br/>* 3.1.7<br/>* 3.2.3<br/><br/>**This playbook will provide you with a first response kit which includes:**<br/><br/>* Hunting<br/>    * Panorama<br/>    * Prisma Cloud Compute<br/>    * XDR XQL queries - set the playbook input **RunXQLHuntingQueries** to 'True' if you would like the XQL to be executed via the playbook.<br/>    * XDR Alerts - Search for new incidents including one or more of Spring RCEs dedicated Cortex XDR signatures<br/>* Remediation<br/>* Mitigations<br/><br/>**Note:** You can execute this playbook using the Incidents view by creating a new incident or by using a dedicated job to schedule the playbook execution. | Optional |
| AutoCloseIncident | Whether to close the incident automatically or continue with manual investigation. | true | Optional |
| BlockIndicatorsAutomatically | Whether to block the indicators automatically. | true | Optional |
| RunXQLHuntingQueries | Whether to hunt using XQL queries. | false | Optional |
| XQLTimeFrame | The XQL search time frame.<br/><br/>Time in relative date or range format \(for example: "1 day", "3 weeks ago", "between 2021-01-01 12:34:56 \+02:00 and 2021-02-01 12:34:56 \+02:00"\). | 7 days | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Spring Core and Cloud Function SpEL RCEs](../doc_files/Spring_Core_and_Cloud_Function_SpEL_RCEs.png)
