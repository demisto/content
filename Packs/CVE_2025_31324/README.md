This pack is part of the [Rapid Breach Response](https://xsoar.pan.dev/marketplace/details/MajorBreachesInvestigationandResponse) pack.


CVE-2025-31324 is a critical zero-day vulnerability affecting the Metadata Uploader component of SAP NetWeaver Visual Composer. The vulnerability arises from missing authorization checks, allowing unauthenticated attackers to upload malicious executable binaries. Exploitation of this flaw can lead to full remote code execution (RCE) on affected systems, posing a significant risk to confidentiality, integrity, and availability.

This flaw allows unauthenticated attackers to upload arbitrary files (e.g., JSP web shells), enabling remote code execution with the same privileges as the SAP application server process.  

[Source: Unit42 - Palo Alto Networks](https://unit42.paloaltonetworks.com/threat-brief-sap-netweaver-cve-2025-31324/)

[View official CVE details on NIST](https://nvd.nist.gov/vuln/detail/CVE-2025-31324)
