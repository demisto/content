This pack is part of the [Rapid Breach Response](https://cortex.marketplace.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse/) pack.

### CVE-2023-34362 - Critical SQL Injection vulnerability in MOVEit Transfer.

#### Summary 

A critical vulnerability has been identified in MOVEit Transfer, a managed file transfer solution. The vulnerability affects versions prior to the latest release and involves improper input validation. Exploiting this vulnerability can lead to remote execution of arbitrary code, potentially resulting in unauthorized access and compromise of sensitive data.

To mitigate the risk associated with this vulnerability, it is crucial for users to update to the latest version of MOVEit Transfer that includes necessary security patches.

**The playbook includes the following tasks:**

**IoCs Collection**
- Blog IoCs download
- Yara Rules download
- Sigma rules download

**Hunting:**
- Microsoft PowerShell hunting script
- Advanced SIEM hunting queries
- Indicators hunting

**Mitigations:**
- Progress official CVE-2023-34362 patch
- Progress mitigation measures
- Detection Rules
    - Yara
    - Sigma


**References:**

[MOVEit Transfer Critical Vulnerability (May 2023)](https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023)

[MOVEit Transfer Critical Vulnerability CVE-2023-34362 Rapid Response](https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response)