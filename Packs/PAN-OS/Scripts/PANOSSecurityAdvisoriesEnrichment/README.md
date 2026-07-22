# PANOSSecurityAdvisories_Enrichment

This script enriches CVEs published by Palo Alto Networks with detailed vulnerability information from the official Palo Alto Networks Security Advisories website <https://security.paloaltonetworks.com>.

## Description

The script retrieves comprehensive vulnerability data including CVSS scores, affected products, version information, exploits, workarounds, and solutions from Palo Alto Networks' security advisories. It supports both CVE identifiers and PAN-SA advisory IDs, automatically determining the appropriate data source and format.

## Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | CVE ID(s) or PAN-SA advisory ID(s) to enrich (array) | Required |

## Outputs

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANOSSecurityAdvisories.Advisory.cve_id | String | CVE ID |
| PANOSSecurityAdvisories.Advisory.title | String | CVE Title |
| PANOSSecurityAdvisories.Advisory.description | String | Vulnerability description |
| PANOSSecurityAdvisories.Advisory.cve_url | String | Link to the PANW Security Advisories page |
| PANOSSecurityAdvisories.Advisory.cvss_score | Number | Base score of CVE |
| PANOSSecurityAdvisories.Advisory.cvss_severity | String | Base severity of CVE (LOW, MEDIUM, HIGH, CRITICAL) |
| PANOSSecurityAdvisories.Advisory.cvethreatscore | Number | Threat Score of the CVE |
| PANOSSecurityAdvisories.Advisory.cvethreatseverity | String | Threat Severity of CVE (LOW, MEDIUM, HIGH, CRITICAL) |
| PANOSSecurityAdvisories.Advisory.cvss_vector_string | String | CVSS Vector indicating metrics of attack |
| PANOSSecurityAdvisories.Advisory.cvss_table | Unknown | Metrics of the vulnerability |
| PANOSSecurityAdvisories.Advisory.affected_list | Unknown | List of affected products, their versions and changes introduced with fixes |
| PANOSSecurityAdvisories.Advisory.cveproductstatus | Unknown | List of affected products with platform information and fixed versions |
| PANOSSecurityAdvisories.Advisory.cpes | Unknown | Affected products defined by CPE |
| PANOSSecurityAdvisories.Advisory.published_date | Date | Date when it was published to the advisories page |
| PANOSSecurityAdvisories.Advisory.last_updated_date | Date | Date when it was last updated on the advisories page |
| PANOSSecurityAdvisories.Advisory.solution | String | Solution provided for the CVE |
| PANOSSecurityAdvisories.Advisory.workaround | String | Workaround for the CVE |
| PANOSSecurityAdvisories.Advisory.configurations | String | Required configurations for exploit |
| PANOSSecurityAdvisories.Advisory.exploits | String | Known exploits of this vulnerability in the field |
| PANOSSecurityAdvisories.Advisory.impact | String | Impact description of the vulnerability |
| PANOSSecurityAdvisories.Advisory.external_cve_list | Unknown | If input CVE is a PAN-SA advisory then list of related non-PANW CVEs |

## Context Example

```json
{
    "PANOSSecurityAdvisories": {
        "Advisory": {
            "cve_id": "CVE-2024-1234",
            "title": "OS Command Injection Vulnerability in PAN-OS",
            "description": "A command injection vulnerability in PAN-OS allows...",
            "cve_url": "https://security.paloaltonetworks.com/CVE-2024-1234",
            "cvss_score": 9.8,
            "cvss_severity": "CRITICAL",
            "cvethreatscore": 9.8,
            "cvethreatseverity": "CRITICAL",
            "cvss_vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "affected_list": [
                {
                    "product": "PAN-OS",
                    "platforms": [""],
                    "versions": [
                        {
                            "version": "10.2.0",
                            "lessThan": "10.2.4-h16",
                            "status": "affected",
                            "changes": [
                                {
                                    "at": "10.2.4-h16",
                                    "status": "unaffected"
                                }
                            ]
                        }
                    ]
                }
            ],
            "published_date": "2024-04-10T16:00:00.000Z",
            "last_updated_date": "2024-04-10T16:00:00.000Z",
            "solution": "This issue is fixed in PAN-OS 10.2.4-h16, PAN-OS 11.0.1, and all later PAN-OS versions.",
            "workaround": "Enable Threat Prevention on all security rules...",
            "external_cve_list": []
        }
    }
}
```

## Human Readable Output

| Field | Value |
|-------|-------|
| CVE ID | CVE-2024-1234 |
| Title | OS Command Injection Vulnerability in PAN-OS |
| CVSS Score | 9.8 |
| Severity | CRITICAL |
| Published Date | 2024-04-10T16:00:00.000Z |
| Solution | This issue is fixed in PAN-OS 10.2.4-h16, PAN-OS 11.0.1, and all later PAN-OS versions. |

## Notes

- The script automatically handles both CVE and PAN-SA format inputs.
- For PAN-SA advisories, the script attempts to retrieve additional CSAF (Common Security Advisory Framework) data.
- Version information is parsed and sorted to provide clear affected/unaffected status.
- CVSS metrics are prioritized by score (highest first) when multiple metrics are available.
- External CVE references are included for PAN-SA advisories when available.
- The script connects to the [Palo Alto Networks Security Advisories](https://security.paloaltonetworks.com/) page for data retrieval.
