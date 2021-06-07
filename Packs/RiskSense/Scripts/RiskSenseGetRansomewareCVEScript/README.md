This script is a helper script for the Ransomware Exposure - RiskSense playbook and retrieves information of CVEs and trending CVEs from host finding details.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | RiskSense |
| Cortex XSOAR Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| trending | Trending is defined by RiskSense as vulnerabilities that are being actively abused by attackers in the wild based on activity in hacker forums and Twitter feeds, as well as analysis of 3rd party threat intelligence sources. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| RiskSense.RansomwareCves.Cve | The ID of the CVE. | String |
| RiskSense.RansomwareCves.CVSS | The CVSS score of the CVE. | Number |
| RiskSense.RansomwareCves.VRR | The risk rate of the host finding. | Number |
| RiskSense.RansomwareCves.ThreatCount | The total number of threats associated with the CVE. | Number |
| RiskSense.RansomwareCves.Trending | This signifies whether the vulnerability \(which is associated with the hostFinding\) has been reported by our internal functions as being trending. | boolean |
| RiskSense.RansomwareCves.VulnLastTrendingOn | Date when last trending vulnerability was found. | String |
| RiskSense.RansomwareCves.Description | A description of the CVE. | String |
| RiskSense.RansomwareCves.Threats.Title | The title of the threat. | String |
| RiskSense.RansomwareCves.Threats.Category | The threat category. | String |
| RiskSense.RansomwareCves.Threats.Severity | The severity level of the threat. | String |
| RiskSense.RansomwareCves.Threats.Description | The threat description. | String |
| RiskSense.RansomwareCves.Threats.Cve | List of CVEs that contain particular threat. | Unknown |
| RiskSense.RansomwareCves.Threats.Source | The source of the threat. | String |
| RiskSense.RansomwareCves.Threats.Published | The time when the threat was published. | String |
| RiskSense.RansomwareCves.Threats.Updated | The time when the threat was last updated. | String |
| RiskSense.RansomwareCves.Threats.ThreatLastTrendingOn | The last time when threat was in trending. | String |
| RiskSense.RansomwareCves.Threats.Trending | Whether the threat is trending. | boolean |
| RiskSense.RansomwareTrendingCves.Cve | The ID of the CVE. | String |
| RiskSense.RansomwareTrendingCves.CVSS | The CVSS score of the CVE. | Number |
| RiskSense.RansomwareTrendingCves.VRR | The risk rate of the host finding. | Number |
| RiskSense.RansomwareTrendingCves.ThreatCount | The total number of threats associated with the CVE. | Number |
| RiskSense.RansomwareTrendingCves.Trending | This signifies whether the vulnerability \(which is associated with the hostFinding\) has been reported by our internal functions as being trending. | boolean |
| RiskSense.RansomwareTrendingCves.VulnLastTrendingOn | Date when last trending vulnerability was found. | String |
| RiskSense.RansomwareTrendingCves.Description | A description of the CVE. | String |
| RiskSense.RansomwareTrendingCves.Threats.Title | The title of the threat. | String |
| RiskSense.RansomwareTrendingCves.Threats.Category | The threat category. | String |
| RiskSense.RansomwareTrendingCves.Threats.Severity | The severity level of the threat. | String |
| RiskSense.RansomwareTrendingCves.Threats.Description | The threat description. | String |
| RiskSense.RansomwareTrendingCves.Threats.Cve | List of CVEs that contain particular threat. | Unknown |
| RiskSense.RansomwareTrendingCves.Threats.Source | The source of the threat. | String |
| RiskSense.RansomwareTrendingCves.Threats.Published | The time when the threat was published. | String |
| RiskSense.RansomwareTrendingCves.Threats.Updated | The time when the threat was last updated. | String |
| RiskSense.RansomwareTrendingCves.Threats.ThreatLastTrendingOn | The last time when threat was in trending. | String |
| RiskSense.RansomwareTrendingCves.Threats.Trending | Whether the threat is trending. | boolean |
| Date.CurrentDate | The current date | String |
| Date.WeekAgoDate | The date that was 7 days ago starting from current date. | String |
| CVECount | The count of the CVEs. | Number |
| TrendingCVECount | The count of the trending CVEs. | Number |
