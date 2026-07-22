CVE feed from the National Vulnerability Database.

This integration was built and tested with version 2.0 of National Vulnerability Database API. See [the NVD Developer API documentation](https://nvd.nist.gov/developers/start-here) for more information.

An API key for this feed can be obtained at [the NIST NVD Developer Website](https://nvd.nist.gov/developers/request-an-api-key)

This integration supports the latest CVSS - Common Vulnerability Scoring System standard - CVSS Version 4.0.

## Configure National Vulnerability Database in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| API Key |  | False |
| Keyword Search | Returns only the CVEs where the word or phrase is found in the description. | False |
| CVSS Severity Filter | Filter CVEs by severity. Queries each CVSS version selected in 'CVSS Versions'. | False |
| CVSS Versions | CVSS versions to query when the severity filter is set. By default, covers most modern CVEs. | False |
| Max Indicators Per Fetch | The maximum number of indicators to fetch per interval. A lower value prevents timeouts during initial syncs with large lookback windows. The fetch will automatically resume from where it left off in the next interval. Without an API key, the recommended maximum is 40000. With an API key, the recommended maximum is 200000. | True |
| First fetch time | How far back should the integration fetch in its first run \(1 day, 2 weeks, 3 months, etc.\) | False |
| Return Known Exploited Vulnerabilities (KEV) only. | See the following for more information: https://nvd.nist.gov/developers/vulnerabilities#cves-hasKev | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
|  |  | False |
| Feed Fetch Interval |  | False |
|  |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |

### NOTE ONE - Sample Debug Output - /var/log/demisto/integration_instance.log

|**Parameter**|**Value**|**Description**|
|---|---|---|
| lastModStartDate|DATE/TIME UTC | The start date for the current CVE fetch cycle. |
| lastModEndDate|DATE/TIME UTC | The end date for the current CVE fetch cycle.|
| Fetch I teration | Integer | Current iteration of the overall fetch from NIST NVD. |
| Iteration Count | Integer | Iteration round through the current fetch cycle. NVD breaks up fetches into chunks to alleviate server load. This is the current count through one of the chunks of CVE data. |
| Total Results for Iteration | Integer | Total results returned for this fetch cycle chunk. |
| Current Total Fetched Indicator Count | Integer | Total number of CVEs fetched overall. |

    lastModStartDate: 2008-09-11T00:00:00.000
    lastModEndDate: 2009-01-09T00:00:00.000 
    Fetch Iteration: 5
    Iteration Count: 0
    Total Results for Iteration: 1
    Current Total Fetched Indicator Count: 4184

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.

### nvd-get-indicators

***
Manually retrieve CVEs from NVD using the history parameter for the duration back to fetch. CVSS severity and version filters can be overridden for this command.

#### Base Command

`!nvd-get-indicators history="7 days"`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| history | Time back to retrieve CVEs, e.g. `7 days`. Possible values are: 7 days. | Required |
| keyword | Keywords to query CVEs by. | Optional |
| limit | The maximum number of CVEs to return. Use a lower value to avoid timeouts due to large lookback windows. Default is 50. | Optional |
| cvss_severity | A comma-separated list of CVSS severities to use for this command. This overrides the instance-level CVSS Severity Filter. If left blank, the instance-level filter is used. Possible values are: CRITICAL, HIGH, MEDIUM, LOW. | Optional |
| cvss_versions | Override the instance-level CVSS Versions for this command. Comma-separated list. Possible values are: CVSS v4, CVSS v3, CVSS v2. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. |
| CVE.CVSS | Number | The CVSS score of the CVE. |
| CVE.Published | Date | The date the CVE was published. |
| CVE.Modified | Date | The date that the CVE was last modified. |
| CVE.Description | String | The description of the CVE. |
| CVE.CVSSVersion | String | The CVSS version used for scoring (e.g. 4.0, 3.1, 2.0). |
| CVE.Severity | String | The CVSS severity level \(e.g. CRITICAL, HIGH, MEDIUM, LOW\). |
