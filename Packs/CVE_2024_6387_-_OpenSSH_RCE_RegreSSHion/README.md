## RegreSSHion Vulnerability (CVE-2024-6387)

On July 1, 2024, a critical signal handler race condition vulnerability was disclosed in OpenSSH servers (sshd) on glibc-based Linux systems. This vulnerability, known as RegreSSHion and tracked as CVE-2024-6387, can result in unauthenticated remote code execution (RCE) with root privileges. This vulnerability has been rated High severity (CVSS 8.1).

#### Impacted Versions

The vulnerability impacts the following OpenSSH server versions:

- OpenSSH versions between 8.5p1 and 9.8p1
- OpenSSH versions earlier than 4.4p1, if they have not been backport-patched against CVE-2006-5051 or patched against CVE-2008-4109

#### Unaffected Versions

The SSH features in PAN-OS are not affected by CVE-2024-6387.

### This pack will provide you with a first response kit which includes:

* **Collect, Extract and Enrich Indicators**
* **Threat Hunting using Cortex XDR - XQL and Prisma Cloud**
* **Mitigations**

Reference:

[Threat Brief: CVE-2024-6387 OpenSSH RegreSSHion Vulnerability
](https://unit42.paloaltonetworks.com/threat-brief-cve-2024-6387-openssh/).
