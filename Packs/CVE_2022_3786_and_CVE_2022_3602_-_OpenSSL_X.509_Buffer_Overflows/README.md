This pack is part of the [Rapid Breach Response](https://cortex.marketplace.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse/) pack.

On November 1, OpenSSL released a [security advisory](https://www.openssl.org/news/secadv/20221101.txt) describing two high severity vulnerabilities within the OpenSSL library, CVE-2022-3786 and CVE-2022-3602. OpenSSL versions from 3.0.0 - 3.0.6 are vulnerable, with 3.0.7 containing the patch for both vulnerabilities. OpenSSL 1.1.1 and 1.0.2 are not affected by this issue.

The vulnerability described in CVE-2022-3602 allows an attacker to obtain a 4-byte overflow on the stack by crafting a malicious email address within the attacker-controlled certificate. The overflow will result in a crash (most likely scenario) or potentially remote code execution (much less likely). In CVE-2022-3786, an attacker can achieve a stack overflow of arbitrary length by crafting a malicious email address within the attacker-controlled certificate.

Both vulnerabilities are “triggered through X.509 certificate verification, specifically, name constraint checking. Note that this occurs after certificate chain signature verification and requires either a CA to have signed the malicious certificate or for the application to continue certificate verification despite failure to construct a path to a trusted issuer.” 

**The playbook includes the following tasks:**
* Hunting for active processes running OpenSSL vulnerable versions using:
    * Cortex XDR
    * Splunk
    * Azure Sentinel
    * Cortex Xpanse
    * Prisma
    * PANOS
  
**Mitigations:**
* OpenSSL official patch

More information:

[Unit42 Threat Brief: CVE-2022-3786 and CVE-2022-3602: OpenSSL X.509 Buffer Overflows](https://unit42.paloaltonetworks.com/openssl-vulnerabilities/)

[NCSC-NL - OpenSSL overview Scanning software](https://github.com/NCSC-NL/OpenSSL-2022/tree/main/scanning)