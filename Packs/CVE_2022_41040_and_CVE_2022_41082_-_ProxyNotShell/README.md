This pack is part of the [Rapid Breach Response](https://cortex.marketplace.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse/) pack.

**UPDATE**
A new method for bypassing ProxyNotShell mitigations was found after being seen exploited in the wild by the Play ransomware gang.
While the original exploit took advantage of the Autodiscover endpoint, the new exploit is using the OWA endpoint leading to SSRF.
The OWASSRF exploit method involves two different vulnerabilities tracked by CVE-2022-41080 and CVE-2022-41082 that allow remote code execution (RCE) via Outlook Web Access (OWA).

This playbook introduces several updates in response to the new discovery:
- Hunting:
    - Detecting possibly successful exploitation of the OWA SSRF vulnerability.
- Mitigations:
    - IIS URL Rewrite rule for the modified exploitation URI path.
- Remediation:
    - Block Indicators - Generic v3 playbook.
  
  
Microsoft is investigating two reported zero-day vulnerabilities affecting Microsoft Exchange Server 2013, Exchange Server 2016, and Exchange Server 2019. The first one, identified as CVE-2022-41040, is a Server-Side Request Forgery (SSRF) vulnerability, and the second one, identified as CVE-2022-41082, allows Remote Code Execution (RCE) when PowerShell is accessible to the attacker.  

Currently, Microsoft is aware of limited targeted attacks using these two vulnerabilities.  In these attacks, CVE-2022-41040 can enable an authenticated attacker to remotely trigger CVE-2022-41082. It should be noted that authenticated access to the vulnerable Exchange Server is necessary to successfully exploit either vulnerability.

This playbook includes the following tasks:

* Collect detection rules, indicators and mitigation tools.
* Exploitation patterns hunting using Cortex XDR - XQL Engine.
* Exploitation patterns hunting using 3rd party SIEM products.
* Indicators hunting.
* Provides Microsoft mitigation and detection capabilities.

**More information:**

[Threat Brief: CVE-2022-41040 and CVE-2022-41082: Microsoft Exchange Server (ProxyNotShell)](https://unit42.paloaltonetworks.com/proxynotshell-cve-2022-41040-cve-2022-41082/)

**References:**

[Analyzing attacks using the Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082](https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/)

[Customer Guidance for Reported Zero-day Vulnerabilities in Microsoft Exchange Server](https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/)

[WARNING: NEW ATTACK CAMPAIGN UTILIZED A NEW 0-DAY RCE VULNERABILITY ON MICROSOFT EXCHANGE SERVER](https://gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html)

[ProxyNotShell— the story of the claimed zero days in Microsoft Exchange](https://doublepulsar.com/proxynotshell-the-story-of-the-claimed-zero-day-in-microsoft-exchange-5c63d963a9e9)