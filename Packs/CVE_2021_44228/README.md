This pack is part of the Rapid Breach Response pack which should be installed as well.

**Critical RCE Vulnerability: log4j - CVE-2021-44228** refers to a 0-day exploit in the popular Java logging library log4j2.

On Dec. 9, 2021, a remote code execution (RCE) vulnerability in Apache log4j 2 was identified being exploited in the wild. Public proof of concept (PoC) code was released and subsequent investigation revealed that exploitation was incredibly easy to perform.

**Affected Version**

Apache Log4j 2.x <= 2.15.0-rc1

**This playbook should be trigger manually and includes the following tasks:**

* Collect related known indicators from several sources.
* Indicators and exploitation patterns hunting using PAN-OS, Cortex XDR and SIEM products.
* Block indicators automatically or manually.

**Mitigations:**

* Apache official CVE-2021-44228 patch.
* Unit42 recommended mitigations.

More information:

[Apache Log4j Vulnerability Is Actively Exploited in the Wild](https://unit42.paloaltonetworks.com/apache-log4j-vulnerability-cve-2021-44228/)

Note: This is a beta playbook, which lets you implement and test pre-release software. Since the playbook is beta, it might contain bugs. Updates to the pack during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the pack to help us identify issues, fix them, and continually improve.

![CVE-2021-44228 - Log4j RCE](https://raw.githubusercontent.com/demisto/content/1f410dd5373e5ce705a8f291b3bc579ddc7a10bd/Packs/CVE_2021_44228/doc_files/CVE-2021-44228_-_Log4j_RCE.png)