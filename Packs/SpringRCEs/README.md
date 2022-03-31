This pack is part of the [Rapid Breach Response](https://xsoar.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse) pack.

**Critical RCE vulnerabilities in Spring Core and Cloud Function SpEL** refers to two 0-day exploits in the popular Spring framework.

Spring Framework is an extremely popular framework used by Java developers to build modern applications. If you rely on the Java stack, it is very likely that your development teams use Spring. In some cases, a single specially crafted request is enough to exploit the vulnerability.

Later, it was discovered that these are two separate vulnerabilities, one in Spring Core and the other in Spring Cloud Function:

* RCE in "Spring Core" is a severe vulnerability, aka Spring4Shell.
* RCE in "Spring Cloud Function", aka CVE-2022-22963.

Spring Cloud Function unaffected versions:

* 3.1.7
* 3.2.3

This pack will provide you with a first response kit which includes:
* Hunting
* Remediation
* Mitigations


More information about the vulnerability:
[CVE-2022-22963: Spring Expression Resource Access Vulnerability](https://tanzu.vmware.com/security/cve-2022-22963)

Note: This is a beta playbook, which lets you implement and test pre-release software. Since the playbook is beta, it might contain bugs. Updates to the pack during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the pack to help us identify issues, fix them, and continually improve.

![Spring Core and Cloud Function SpEL RCEs](https://raw.githubusercontent.com/demisto/content/3066f91bb206526bdfb7535af33db1603a8d5b5f/Packs/SpringRCEs/doc_files/Spring_Core_and_Cloud_Function_SpEL_RCEs.png)