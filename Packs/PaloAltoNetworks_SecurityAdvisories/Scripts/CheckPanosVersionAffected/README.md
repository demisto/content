Checks if the given PAN-OS version number is affected by the given list of vulnerabilities from the pan-advisories-get-advisories command.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| version | The PAN-OS version - ex 9.1.0 |
| advisories | The list of advisories, produced by pan-advisories-get-advisories |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MatchingSecurityAdvisory.data_type | The type of advisory this is | String |
| MatchingSecurityAdvisory.data_format | The format of the advisory, such as MITRE | String |
| MatchingSecurityAdvisory.cve_id | The ID of the CVE described by this advisory | String |
| MatchingSecurityAdvisory.cve_date_public | The date this CVE was released | String |
| MatchingSecurityAdvisory.cve_title | The name of this CVE | String |
| MatchingSecurityAdvisory.affects_vendor_name | The name of the product this affects, such as PAN-OS | String |
| MatchingSecurityAdvisory.description | Human readable description of Advisory | String |
| MatchingSecurityAdvisory.affected_version_list | List of PAN-OS affected versions exactly | String |
| MatchingSecurityAdvisory.cvss_score | CVSS Score of matched vulnerability | Unknown |
| MatchingSecurityAdvisory.cvss_severity | CVSS Severity of matched vulnerability | Unknown |
