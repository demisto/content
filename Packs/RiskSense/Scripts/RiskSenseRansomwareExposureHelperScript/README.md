This script is a helper script of Ransomware Exposure - RiskSense playbook and performs a particular task based on module_name arguments.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | RiskSense |
| Demisto Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Ransomware Exposure - RiskSense

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| module_name | Script will execute particular function based on module_name |

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
| Date.CurrentDate | The current date. | String |
| Date.WeekAgoDateDate | The date that was 7 days ago starting from current date | String |

## Script Example
```!RiskSenseRansomwareExposureHelperScript module_name="Ransomware"```

## Context Example
```
{
  "RiskSense.RansomwareCves": [
    {
      "CVSS": 5,
      "Cve": "CVE-2010-1429",
      "Description": "Red Hat JBoss Enterprise Application Platform (aka JBoss EAP or JBEAP) 4.2 before 4.2.0.CP09 and 4.3 before 4.3.0.CP08 allows remote attackers to obtain sensitive information about \"deployed web contexts\" via a request to the status servlet, as demonstrated by a full=true query string.  NOTE: this issue exists because of a CVE-2008-3273 regression.",
      "ThreatCount": 4,
      "Threats": [
        {
          "Category": "Ransomware",
          "Cve": "CVE-2010-1429",
          "Description": "",
          "Published": "2011-10-24T00:00:00",
          "Severity": null,
          "Source": "SYMANTEC",
          "ThreatLastTrendingOn": null,
          "Title": "Perl.Bossworm",
          "Trending": false,
          "Updated": "2020-04-28T15:50:07"
        }
      ],
      "Trending": false,
      "VRR": 7.05,
      "VulnLastTrendingOn": "Not Found"
    }
  ]
}
```

## Human Readable Output
### List of CVEs that have ransomware threat
|CVE ID|CVSS Score|VRR Score|Threat Count|Last Trending On Date|Trending|
|---|---|---|---|---|---|
| CVE-2010-1429 | 5 | 7.05 | 1 | 2020-04-28 | true |


## Script Example
```!RiskSenseRansomwareExposureHelperScript module_name="Trending Ransomware"```

## Context Example
```
{
  "RiskSense.RansomwareTrendingCves": [
    {
      "CVSS": 5,
      "Cve": "CVE-2010-1429",
      "Description": "Red Hat JBoss Enterprise Application Platform (aka JBoss EAP or JBEAP) 4.2 before 4.2.0.CP09 and 4.3 before 4.3.0.CP08 allows remote attackers to obtain sensitive information about \"deployed web contexts\" via a request to the status servlet, as demonstrated by a full=true query string.  NOTE: this issue exists because of a CVE-2008-3273 regression.",
      "ThreatCount": 4,
      "Threats": [
        {
          "Category": "Ransomware",
          "Cve": "CVE-2010-1429",
          "Description": "",
          "Published": "2011-10-24T00:00:00",
          "Severity": null,
          "Source": "SYMANTEC",
          "ThreatLastTrendingOn": null,
          "Title": "Perl.Bossworm",
          "Trending": false,
          "Updated": "2020-04-28T15:50:07"
        }
      ],
      "Trending": false,
      "VRR": 7.05,
      "VulnLastTrendingOn": "Not Found"
    }
  ]
}

```

## Human Readable Output
### List of CVEs which are ransomware trending
|CVE ID|CVSS Score|VRR Score|Threat Count|Last Trending On Date|Trending|
|---|---|---|---|---|---|
| CVE-2010-1429 | 5 | 7.05 | 1 | 2020-04-28 | true |
