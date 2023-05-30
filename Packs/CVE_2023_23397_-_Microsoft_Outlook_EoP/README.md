This pack is part of the [Rapid Breach Response](https://cortex.marketplace.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse/) pack.

### CVE-2023-23397 - Critical Elevation of Privilege vulnerability in Microsoft Outlook 

#### Summary 
Microsoft Threat Intelligence discovered limited, targeted abuse of a vulnerability in Microsoft Outlook for Windows that allows for new technology LAN manager (NTLM) credential theft. Microsoft has released CVE-2023-23397 to address the critical elevation of privilege (EoP) vulnerability affecting Microsoft Outlook for Windows. 

**The playbook includes the following tasks:**

**Hunting:**
- Microsoft PowerShell hunting script
- Advanced SIEM hunting queries
- Indicators hunting

**Mitigations:**
- Microsoft official CVE-2023-23397 patch
- Microsoft workarounds
- Detection Rules
    - Yara

**References:**

[Microsoft Mitigates Outlook Elevation of Privilege Vulnerability](https://msrc.microsoft.com/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
[CVE-2023-23397 Audit & Eradication Script](https://github.com/microsoft/CSS-Exchange/blob/a4c096e8b6e6eddeba2f42910f165681ed64adf7/docs/Security/CVE-2023-23397.md)
[Neo23x0 Yara Rules](https://github.com/Neo23x0/signature-base/blob/master/yara/expl_outlook_cve_2023_23397.yar)
