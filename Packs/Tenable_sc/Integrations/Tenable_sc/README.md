Use the Tenable.sc integration to get a real-time, continuous assessment of your security posture so you can find and fix vulnerabilities faster.
All data in Tenable.sc is managed using group level permissions. If you have several groups, data (scans, scan results, assets, etc) can be viewable but not manageable. Users with Security Manager role  can manage everything. These permissions come into play when multiple groups are in use.
It is important to know what data is manageable for the user in order to work with the integration.
This integration was integrated and tested with Tenable.sc v5.7.0.

## Use cases:

    * Create and run scans.
    * Launch and manage scan results and the found vulnerabilities.
    * Create and view assets.
    * View policies, repositories, credentials, users and more system information.
    * View and real-time receiving of alerts.

## Configure Tenable.sc in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://192.168.0.1) | The server URL. | True |
| Access key | See the help for instructions to generate the access key. | False |
| Secret key |  | False |
| Username | The Username is either admin or secman \(depend on the role you want to log into\) and your password to the tenable server. | False |
| Password |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | The timestamp to start the fetch from. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tenable-sc-list-scans

***
Requires security manager role. Get a list of Tenable.sc existing scans.

#### Base Command

`tenable-sc-list-scans`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| manageable | Whether to return only manageable scans. Returns both usable and manageable scans by default. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Scan.Name | string | Scan name. | 
| TenableSC.Scan.ID | number | Scan ID. | 
| TenableSC.Scan.Description | string | Scan description. | 
| TenableSC.Scan.Policy | string | Scan policy name. | 
| TenableSC.Scan.Group | string | Scan policy owner group name. | 
| TenableSC.Scan.Owner | string | Scan policy owner user name. | 

#### Human Readable Output

### Tenable.sc Scans

|ID|Name|Description|Policy|Group|Owner|
|---|---|---|---|---|---|
| 3 | test_scan_2023 | Test scan | Network Scan | Full Access | secman |

### tenable-sc-launch-scan

***
Requires security manager role. Launch an existing scan from Tenable.sc. Set polling to true to follow the scan and receive results when scan is over.

#### Base Command

`tenable-sc-launch-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | Scan ID, can be retrieved from list-scans command. | Required | 
| diagnostic_target | Valid IP/Hostname of a specific target to scan. Must be provided with diagnosticPassword. | Optional | 
| diagnostic_password | Non empty string password. | Optional | 
| timeout_in_seconds | Relevant only when polling is true. Default is 3 hours. The timeout in seconds until polling ends. Default is 10800. | Optional | 
| polling | Default is false. When set to true, will keep polling results until scan is done and return the formatted scan results. Possible values are: true, false. Default is false. | Optional | 
| scan_results_id | Deprecated. Scan results ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanResults.Name | string | Scan name. | 
| TenableSC.ScanResults.Status | string | Scan status. | 
| TenableSC.ScanResults.ID | string | Scan Results ID. | 
| TenableSC.ScanResults.OwnerID | string | Relevant only when polling is false. Scan owner ID. | 
| TenableSC.ScanResults.JobID | string | Relevant only when polling is false. Job ID. | 
| TenableSC.ScanResults.ScannedIPs | number | Relevant only when polling is true. Scan number of scanned IPs. | 
| TenableSC.ScanResults.StartTime | date | Relevant only when polling is true. Scan start time. | 
| TenableSC.ScanResults.EndTime | date | Relevant only when polling is true. Scan end time. | 
| TenableSC.ScanResults.Checks | number | Relevant only when polling is true. Scan completed checks. | 
| TenableSC.ScanResults.RepositoryName | string | Relevant only when polling is true. Scan repository name. | 
| TenableSC.ScanResults.Description | string | Relevant only when polling is true. Scan description. | 
| TenableSC.ScanResults.Vulnerability.ID | number | Relevant only when polling is true. Scan vulnerability ID. | 
| TenableSC.ScanResults.Vulnerability.Name | string | Relevant only when polling is true. Scan vulnerability Name. | 
| TenableSC.ScanResults.Vulnerability.Family | string | Relevant only when polling is true. Scan vulnerability family. | 
| TenableSC.ScanResults.Vulnerability.Severity | string | Relevant only when polling is true. Scan vulnerability severity. | 
| TenableSC.ScanResults.Vulnerability.Total | number | Relevant only when polling is true. Scan vulnerability total hosts. | 
| TenableSC.ScanResults.Policy | string | Relevant only when polling is true. Scan policy. | 
| TenableSC.ScanResults.Group | string | Relevant only when polling is true. Scan owner group name. | 
| TenableSC.ScanResults.Owner | string | Relevant only when polling is true. Scan owner user name. | 
| TenableSC.ScanResults.Duration | number | Relevant only when polling is true. Scan duration in minutes. | 
| TenableSC.ScanResults.ImportTime | date | Relevant only when polling is true. Scan import time. | 

#### Human Readable Output

When polling is set to false:
### Tenable.sc Scan

|Name|ID|OwnerID|JobID|Status|
|---|---|---|---|---|
| test_scan_2023 | 169 | 38 | 118864 | Queued |

When polling is set to true:
### Tenable.sc Scan 130 Report

|ID|Name|Description|Policy|Group|Owner|ScannedIPs|StartTime|EndTime|Duration|Checks|ImportTime|RepositoryName|Status|Scan Type|Completed IPs|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 130 | test_scan_2023 | Test scan 2023 | Network Scan | Full Access | hayun_test_sec_man | 156 | 2023-05-16T12:18:10Z | 2023-05-16T17:20:00Z | 301.8333333333333 | 22649640 | 2023-05-16T17:20:02Z | Local | Completed | regular | 156 |

### tenable-sc-get-vulnerability

***
Requires security manager role. Get details about a given vulnerability from a given Tenable.sc scan.

#### Base Command

`tenable-sc-get-vulnerability`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | Vulnerability ID from the scan-report command. | Required | 
| scan_results_id | Scan results ID from the scan-report command. | Optional | 
| query_id | Can be created via the Tenable.sc UI &gt; Analysis &gt; queries. Can be retrieved from the tenable-sc-list-query command. | Optional | 
| sort_direction | The direction in which the results should be sorted. Requires companion parameter, sort_field. Possible values are: ASC, DESC. Default is ASC. | Optional | 
| sort_field | Which field to sort by, For vulnerabilities data, Tenable recommends you sort by severity. Default is severity. | Optional | 
| source_type | When the source_type is "individual", a scan_results_id must be provided, otherwise "query_id" must be provided. cumulative — Analyzes cumulative vulnerabilities. patched — Analyzes mitigated vulnerabilities. Possible values are: individual, cumulative, patched. Default is individual. | Optional | 
| limit | The number of objects to return in one response (maximum limit is 200). Default is 50. | Optional | 
| page | The page to return, starting from 0. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanResults.ID | number | Scan results ID. | 
| TenableSC.ScanResults.Vulnerability.ID | number | Vulnerability plugin ID. | 
| TenableSC.ScanResults.Vulnerability.Name | string | Vulnerability name. | 
| TenableSC.ScanResults.Vulnerability.Description | string | Vulnerability description. | 
| TenableSC.ScanResults.Vulnerability.Type | string | Vulnerability type. | 
| TenableSC.ScanResults.Vulnerability.Severity | string | Vulnerability Severity. | 
| TenableSC.ScanResults.Vulnerability.Synopsis | string | Vulnerability Synopsis. | 
| TenableSC.ScanResults.Vulnerability.Solution | string | Vulnerability Solution. | 
| TenableSC.ScanResults.Vulnerability.Published | date | Vulnerability publish date. | 
| TenableSC.ScanResults.Vulnerability.CPE | string | Vulnerability CPE. | 
| TenableSC.ScanResults.Vulnerability.CVE | Unknown | Vulnerability CVE. | 
| TenableSC.ScanResults.Vulnerability.ExploitAvailable | boolean | Vulnerability exploit available. | 
| TenableSC.ScanResults.Vulnerability.ExploitEase | string | Vulnerability exploit ease. | 
| TenableSC.ScanResults.Vulnerability.RiskFactor | string | Vulnerability risk factor. | 
| TenableSC.ScanResults.Vulnerability.CVSSBaseScore | number | Vulnerability CVSS base score. | 
| TenableSC.ScanResults.Vulnerability.CVSSTemporalScore | number | Vulnerability CVSS temporal score. | 
| TenableSC.ScanResults.Vulnerability.CVSSVector | string | Vulnerability CVSS vector. | 
| TenableSC.ScanResults.Vulnerability.PluginDetails | Unknown | Vulnerability plugin details. | 
| CVE.ID | Unknown | CVE ID. | 
| TenableSC.ScanResults.Vulnerability.Host.IP | string | Vulnerability Host IP. | 
| TenableSC.ScanResults.Vulnerability.Host.MAC | string | Vulnerability Host MAC. | 
| TenableSC.ScanResults.Vulnerability.Host.Port | number | Vulnerability Host Port. | 
| TenableSC.ScanResults.Vulnerability.Host.Protocol | string | Vulnerability Host Protocol. | 

#### Human Readable Output

## Vulnerability: FTP Server Detection (10092)

### Synopsis

An FTP server is listening on a remote port.

### Description

It is possible to obtain the banner of the remote FTP server by connecting to a remote port.

### Solution

### Hosts

|IP|MAC|Port|Protocol|
|---|---|---|---|
| {IP} | {MAC} | 21 | TCP |

### Risk Information

|RiskFactor|
|---|
| None |

### Exploit Information

|ExploitAvailable|
|---|
| false |

### Plugin Details

|CheckType|Family|Modified|Published|
|---|---|---|---|
| remote | Service detection | 2019-11-22T17:00:00Z | 1999-10-12T16:00:00Z |

### Vulnerability Information

**No entries.**

### tenable-sc-get-scan-status

***
Requires security manager role. Get the status of a specific scan in Tenable.sc.

#### Base Command

`tenable-sc-get-scan-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_results_id | Scan results ID from the launch-scan command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanResults.Status | string | Scan status. | 
| TenableSC.ScanResults.Name | string | Scan Name. | 
| TenableSC.ScanResults.Description | string | Scan description. | 
| TenableSC.ScanResults.ID | string | Scan results ID. | 
| TenableSC.ScanResults.Error | string | Will appear only in case of error in the scan, include the cause for the failure. | 

#### Human Readable Output

### Tenable.sc Scan Status

|ID|Name|Status|Description|
|---|---|---|---|
| 169 | test_scan_2023 | Running | Test scan 2023 |

### tenable-sc-get-scan-report

***
Requires security manager role. Get a single report with Tenable.sc scan results. In case of `Importstatus = Error` (The results import wasn't finished), the vulnerabilities section will not be added to the results.

#### Base Command

`tenable-sc-get-scan-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_results_id | Scan results ID. | Required | 
| vulnerability_severity | Comma-separated list of severity values of vulnerabilities to retrieve. Default is Critical,High,Medium,Low,Info. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanResults.ID | number | Scan results ID. | 
| TenableSC.ScanResults.Name | string | Scan name. | 
| TenableSC.ScanResults.Status | string | Scan status. | 
| TenableSC.ScanResults.ScannedIPs | number | Scan number of scanned IPs. | 
| TenableSC.ScanResults.StartTime | date | Scan start time. | 
| TenableSC.ScanResults.EndTime | date | Scan end time. | 
| TenableSC.ScanResults.Checks | number | Scan completed checks. | 
| TenableSC.ScanResults.RepositoryName | string | Scan repository name. | 
| TenableSC.ScanResults.Description | string | Scan description. | 
| TenableSC.ScanResults.Vulnerability.ID | number | Scan vulnerability ID. | 
| TenableSC.ScanResults.Vulnerability.Name | string | Scan vulnerability Name. | 
| TenableSC.ScanResults.Vulnerability.Family | string | Scan vulnerability family. | 
| TenableSC.ScanResults.Vulnerability.Severity | string | Scan vulnerability severity. | 
| TenableSC.ScanResults.Vulnerability.Total | number | Scan vulnerability total hosts. | 
| TenableSC.ScanResults.Policy | string | Scan policy. | 
| TenableSC.ScanResults.Group | string | Scan owner group name. | 
| TenableSC.ScanResults.Owner | string | Scan owner user name. | 
| TenableSC.ScanResults.Duration | number | Scan duration in minutes. | 
| TenableSC.ScanResults.ImportTime | date | Scan import time. | 
| TenableSC.ScanResults.IsScanRunning | boolean | Whether the scan is still running. | 
| TenableSC.ScanResults.ImportStatus | string | Scan import status. | 

### Human Readable Output

### Tenable.sc Scan 150 Report

|ID|Name|Policy|Group|Owner|ScannedIPs|StartTime|EndTime|Duration|Checks|ImportTime|RepositoryName|Status|Scan Type|Completed IPs|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 150 | my_Test_scan | Plugin #1 | Full Access | yuv | 115 | 2023-05-18T13:12:51Z | 2023-05-18T13:45:53Z | 33.03333333333333 | 21275 | 2023-05-18T13:45:57Z | Local | Completed | regular | 115 |

### Vulnerabilities

|ID|Name|Family|Severity|Total|
|---|---|---|---|---|
| 11219 | Nessus SYN scanner | Port scanners | Info | 109 |

### tenable-sc-list-credentials

***
Requires security manager role. Get a list of Tenable.sc credentials.

#### Base Command

`tenable-sc-list-credentials`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| manageable | Whether to return only manageable scan credentials. Returns both usable and manageable by default. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Credential.Name | string | Credential name. | 
| TenableSC.Credential.ID | number | Credential ID. | 
| TenableSC.Credential.Description | string | Credential description. | 
| TenableSC.Credential.Type | string | Credential type. | 
| TenableSC.Credential.Tag | string | Credential tag. | 
| TenableSC.Credential.Group | string | Credential owner group name. | 
| TenableSC.Credential.Owner | string | Credential owner user name. | 
| TenableSC.Credential.LastModified | date | Credential last modified time. | 

#### Human Readable Output

### Tenable.sc Credentials

|ID|Name|Type|Group|LastModified|
|---|---|---|---|---|
| 1 | Windows server | windows |  | 2023-02-14T11:44:12Z |
| 2 | SSH linux | ssh |  | 2023-02-15T09:11:10Z |
| 3 | Windows clients | windows |  | 2023-02-15T12:32:45Z |

### tenable-sc-list-policies

***
Requires security manager role. Get a list of Tenable.sc scan policies.

#### Base Command

`tenable-sc-list-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| manageable | Whether to return only manageable scan policies. Returns both usable and manageable by default. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanPolicy.Name | string | Scan policy name. | 
| TenableSC.ScanPolicy.ID | number | Scan policy ID. | 
| TenableSC.ScanPolicy.Description | string | Scan policy description. | 
| TenableSC.ScanPolicy.Tag | string | Scan policy tag. | 
| TenableSC.ScanPolicy.Group | string | Scan policy owner group name. | 
| TenableSC.ScanPolicy.Owner | string | Scan policy owner user name. | 
| TenableSC.ScanPolicy.LastModified | date | Scan policy last modified time. | 
| TenableSC.ScanPolicy.Type | string | Scan policy type. | 

#### Human Readable Output

### Tenable.sc Scan Policies

|ID|Name|Description|Type|Group|Owner|LastModified|
|---|---|---|---|---|---|---|
| 1 | Network Scan |  | Basic Network Scan |  |  | 2023-02-09T14:58:26Z |
| 2 | D Advanced Scan | D Advanced Scan | Advanced Scan |  |  | 2023-02-13T13:02:22Z |

### tenable-sc-list-report-definitions

***
Requires security manager role. Get a list of Tenable.sc report definitions.

#### Base Command

`tenable-sc-list-report-definitions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| manageable | Whether to return only manageable reports. Returns both usable and manageable by default. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ReportDefinition.Name | string | Report definition name. | 
| TenableSC.ReportDefinition.ID | number | Report definition ID. | 
| TenableSC.ReportDefinition.Description | string | Report definition description. | 
| TenableSC.ReportDefinition.Type | string | Report definition type. | 
| TenableSC.ReportDefinition.Group | string | Report definition owner group name. | 
| TenableSC.ReportDefinition.Owner | string | Report definition owner user name. | 

#### Human Readable Output

### Tenable.sc Report Definitions

|ID|Name|Description|Type|Group|Owner|
|---|---|---|---|---|---|
| 2 | Critical and Exploitable Vulnerabilities Report | Test | pdf | Full Access | test |

### tenable-sc-list-repositories

***
Requires security manager role. Get a list of Tenable.sc scan repositories.

#### Base Command

`tenable-sc-list-repositories`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanRepository.Name | string | Scan Repository name. | 
| TenableSC.ScanRepository.ID | number | Scan Repository ID. | 
| TenableSC.ScanRepository.Description | string | Scan Repository. | 

#### Human Readable Output

### Tenable.sc Scan Repositories

|ID|Name|
|---|---|
| 1 | Local |

### tenable-sc-list-zones

***
Requires admin role. Get a list of Tenable.sc scan zones.

#### Base Command

`tenable-sc-list-zones`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanZone.Name | string | Scan Zone name. | 
| TenableSC.ScanZone.ID | number | Scan Zone ID. | 
| TenableSC.ScanZone.Description | string | Scan Zone description. | 
| TenableSC.ScanZone.IPList | unknown | Scan Zone IP list. | 
| TenableSC.ScanZone.ActiveScanners | number | Scan Zone active scanners. | 
| TenableSC.ScanZone.Scanner.Name | string | Scanner name. | 
| TenableSC.ScanZone.Scanner.ID | number | Scanner ID. | 
| TenableSC.ScanZone.Scanner.Description | string | Scanner description. | 
| TenableSC.ScanZone.Scanner.Status | number | Scanner status. | 

#### Human Readable Output

### Tenable.sc Scan Zones

|ID|Name|IPList|activeScanners|
|---|---|---|---|
| 1 | Default Scan Zone | ip | 1 |

### Tenable.sc Scanners

|ID|Name|Status|
|---|---|---|
| 2 | RHEL6 Scanner | 1 |

### tenable-sc-create-scan

***
Requires security manager role. Create a scan on Tenable.sc

#### Base Command

`tenable-sc-create-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Scan name. | Required | 
| policy_id | Policy ID, can be retrieved from the list-policies command. | Required | 
| plugin_id | Plugin ID. | Optional | 
| description | Scan description. | Optional | 
| repository_id | Scan Repository ID. Can be retrieved from the list-repositories command. | Required | 
| zone_id | Scan zone ID (default is all zones). Can be retrieved from the list-zones command. | Optional | 
| schedule | Schedule for the scan. Possible values are: dependent, ical, never, rollover, now. | Optional | 
| asset_ids | Either all assets or comma-separated asset IDs to scan. Can be retrieved from the list-assets command. Possible values are: All, AllManageable. | Optional | 
| scan_virtual_hosts | Whether to include virtual hosts. Default is false. Possible values are: true, false. | Optional | 
| ip_list | Comma-separated IPs to scan, e.g., 10.0.0.1,10.0.0.2 . | Optional | 
| report_ids | Comma- separated list of report definition IDs to create post-scan. Can be retrieved from the list-report-definitions command. | Optional | 
| credentials | Comma-separated credentials IDs to use. Can be retrieved from the list-credentials command. | Optional | 
| timeout_action | Scan timeout action. Default is import. Possible values are: discard, import, rollover. | Optional | 
| max_scan_time | Maximum scan run time in hours, Default is 1. | Optional | 
| dhcp_tracking | Track hosts which have been issued new IP address, (e.g., DHCP). Possible values are: true, false. | Optional | 
| rollover_type | Scan rollover type. Possible values are: nextDay. | Optional | 
| dependent_id | Dependent scan ID in case of a dependent schedule. Can be retrieved from the list-scans command. | Optional | 
| time_zone | The timezone for the given start_time, Possible values can be found here: https://docs.oracle.com/middleware/1221/wcs/tag-ref/MISC/TimeZones.html. | Optional | 
| start_time | The scan start time in the format of YYYY-MM-DD:HH:MM:SS or relative timestamp (i.e., now, 3 days). | Optional | 
| repeat_rule_freq | Specifies repeating events based on an interval of a repeat_rule_freq or more. Possible values are: HOURLY, DAILY, WEEKLY, MONTHLY, YEARLY. | Optional | 
| repeat_rule_interval | The number of repeat_rule_freq between each interval (for example: If repeat_rule_freq=DAILY and repeat_rule_interval=8 it means every eight days.). | Optional | 
| repeat_rule_by_day | A comma-separated list of days of the week to run the schedule. Possible values are: SU,MO,TU,WE,TH,FR,SA. | Optional | 
| enabled | The "enabled" field can only be set to "false" for schedules of type "ical". For all other schedules types, "enabled" is set to "true". Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Scan.ID | string | Scan ID. | 
| TenableSC.Scan.CreatorID | string | Scan's creator ID. | 
| TenableSC.Scan.Name | string | Scan Name. | 
| TenableSC.Scan.Type | string | Scan type. | 
| TenableSC.Scan.CreatedTime | date | Scan creation time. | 
| TenableSC.Scan.OwnerName | string | Scan owner Username. | 
| TenableSC.Scan.Reports | unknown | Scan report definition IDs. | 

#### Human Readable Output

### Scan created successfully

|ID|CreatorID|Name|Type|CreationTime|
|---|---|---|---|---|
| 70 | 39 | my_name | policy | 2023-05-24T12:33:03Z |

### tenable-sc-delete-scan

***
Requires security manager role. Delete a scan in Tenable.sc.

#### Base Command

`tenable-sc-delete-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | Scan ID. Can be retrieved from the the list-scans command. | Required | 

#### Context Output

There is no context output for this command.

#### Human Readable Output

Scan {scan_id} was deleted successfully.

### tenable-sc-list-assets

***
Requires security manager role. Get a list of Tenable.sc assets.

#### Base Command

`tenable-sc-list-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| manageable | Whether to return only manageable assets. Returns both usable and manageable by default. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Asset.ID | string | Asset ID. | 
| TenableSC.Asset.Name | string | Asset name. | 
| TenableSC.Asset.HostCount | number | Asset host IPs count. | 
| TenableSC.Asset.Type | string | Asset type. | 
| TenableSC.Asset.Tag | string | Asset tag. | 
| TenableSC.Asset.Owner | string | Asset owner username. | 
| TenableSC.Asset.Group | string | Asset group. | 
| TenableSC.Asset.LastModified | date | Asset last modified time. | 

#### Human Readable Output

### Tenable.sc Assets

|ID|Name|Tag|Owner|Type|HostCount|LastModified|
|---|---|---|---|---|---|---|
| 0 | All Defined Ranges |  |  | static | 0 | 2023-01-09T13:13:52Z |
| 1 | asset_1_name |  | test | dynamic | 106 | 2023-05-21T09:12:52Z |
| 2 | Systems that have been Scanned |  | test | dynamic | 152 | 2023-01-09T13:14:43Z |

### tenable-sc-create-asset

***
Requires security manager role. Create an asset in Tenable.sc with provided IP addresses.

#### Base Command

`tenable-sc-create-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Asset name. | Required | 
| description | Asset description. | Optional | 
| owner_id | Asset owner ID. Default is the Session User ID. Can be retrieved from the list-users command. | Optional | 
| tag | Asset tag. | Optional | 
| ip_list | Comma-separated list of IPs to include in the asset, e.g., 10.0.0.2,10.0.0.4. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Asset.Name | string | Asset name. | 
| TenableSC.Asset.ID | string | Asset ID. | 
| TenableSC.Asset.OwnerName | string | Asset owner name. | 
| TenableSC.Asset.Tags | string | Asset tags. | 

#### Human Readable Output

### Asset created successfully

|ID|Name|OwnerName|
|---|---|---|
| 42 | example output | yuv |

### tenable-sc-get-asset

***
Requires security manager role. Get details for a given asset in Tenable.sc.

#### Base Command

`tenable-sc-get-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID that can be retrieved from the list-assets command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Asset.ID | number | Asset ID. | 
| TenableSC.Asset.Name | string | Asset name. | 
| TenableSC.Asset.Description | string | Asset description. | 
| TenableSC.Asset.Tag | string | Asset tag. | 
| TenableSC.Asset.Modified | date | Asset last modified time. | 
| TenableSC.Asset.Owner | string | Asset owner user name. | 
| TenableSC.Asset.Group | string | Asset owner group. | 
| TenableSC.Asset.IPs | unknown | Asset viewable IPs. | 

#### Human Readable Output

### Tenable.sc Asset

|ID|Name|Description|Created|Modified|Owner|Group|IPs|
|---|---|---|---|---|---|---|---|
| 1 | asset_1_name | asset_1_description | 2023-01-09T13:14:43Z | 2023-05-21T09:12:52Z | test | Full Access | {IPs_list} |

### tenable-sc-delete-asset

***
Requires security manager role. Delete the asset with the given ID from Tenable.sc.

#### Base Command

`tenable-sc-delete-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required | 

#### Context Output

There is no context output for this command.

#### Human Readable Output

Asset {asset_id} was deleted successfully.

### tenable-sc-list-alerts

***
Requires security manager role. List alerts from Tenable.sc.

#### Base Command

`tenable-sc-list-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| manageable | Whether to return only manageable alerts. Returns both usable and manageable by default. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Alert.ID | string | Alert ID. | 
| TenableSC.Alert.Name | string | Alert name. | 
| TenableSC.Alert.Description | string | Alert description. | 
| TenableSC.Alert.State | string | Alert state. | 
| TenableSC.Alert.Actions | string | Alert actions. | 
| TenableSC.Alert.LastTriggered | date | Alert last triggered time. | 
| TenableSC.Alert.LastEvaluated | date | Alert last evaluated time. | 
| TenableSC.Alert.Group | string | Alert owner group name. | 
| TenableSC.Alert.Owner | string | Alert owner user name. | 

#### Human Readable Output

### Tenable.sc Alerts

|ID|Name|Actions|State|LastTriggered|LastEvaluated|Group|Owner|
|---|---|---|---|---|---|---|---|
| 1 | Test Alert 1 | ticket | Triggered | 2023-02-16T07:13:08Z | 2023-05-23T13:30:01Z | Full Access | lmanager |
| 2 | Test Alert 2 | scan | Triggered | 2023-02-16T07:14:07Z | 2023-05-24T12:14:08Z | Full Access | lmanager |

### tenable-sc-get-alert

***
Requires security manager role. Get information about a given alert in Tenable.sc.

#### Base Command

`tenable-sc-get-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. Can be retrieved from the list-alerts command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Alert.ID | string | Alert ID. | 
| TenableSC.Alert.Name | string | Alert name. | 
| TenableSC.Alert.Description | string | Alert description. | 
| TenableSC.Alert.State | string | Alert state. | 
| TenableSC.Alert.Condition.Trigger | string | Alert trigger. | 
| TenableSC.Alert.LastTriggered | date | Alert last triggered time. | 
| TenableSC.Alert.Condition.Query | string | Alert query name. | 
| TenableSC.Alert.Condition.Filter.Name | string | Alert query filter name. | 
| TenableSC.Alert.Condition.Filter.Values | Unknown | Alert query filter values. | 
| TenableSC.Alert.Action.Type | string | Alert action type. | 
| TenableSC.Alert.Action.Values | Unknown | Alert action values. | 

#### Human Readable Output

### Tenable.sc Alert

ID|Name|LastTriggered|State|Behavior|
|---|---|---|---|---|
| 1 | Test Alert 1 | 2023-02-16T07:13:08Z | Triggered | Execute only on first trigger |

### Condition

|Trigger|Query|
|---|---|
| sumip \u003e= 10 | Query for alert 'Test Alert 1' at 1676531587 |

### Actions

|Type|Values|
|---|---|
| ticket | lmanager |

### tenable-sc-get-device

***
Requires security manager role. Gets the specified device information.

#### Base Command

`tenable-sc-get-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A valid IP address of a device. | Optional | 
| dns_name | DNS name of a device. | Optional | 
| repository_id | Repository ID to get the device from. Can be retrieved from the list-repositories command. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Device.IP | string | Device IP address. | 
| TenableSC.Device.UUID | string | Device UUID. | 
| TenableSC.Device.RepositoryID | string | Device repository ID. | 
| TenableSC.Device.MacAddress | string | Device Mac address. | 
| TenableSC.Device.NetbiosName | string | Device Netbios name. | 
| TenableSC.Device.DNSName | string | Device DNS name. | 
| TenableSC.Device.OS | string | Device operating system. | 
| TenableSC.Device.OsCPE | string | Device Common Platform Enumeration. | 
| TenableSC.Device.LastScan | date | Device's last scan time. | 
| TenableSC.Device.RepositoryName | string | Device repository name. | 
| TenableSC.Device.TotalScore | number | Device total threat score. | 
| TenableSC.Device.LowSeverity | number | Device total threat scores with low severity. | 
| TenableSC.Device.MediumSeverity | number | Device total threat scores with medium severity. | 
| TenableSC.Device.HighSeverity | number | Device total threat scores with high severity. | 
| TenableSC.Device.CriticalSeverity | number | Device total threat scores with critical severity. | 
| Endpoint.IPAddress | string | Endpoint IP address. | 
| Endpoint.Hostname | string | Endpoint DNS name. | 
| Endpoint.MACAddress | string | Endpoint MAC address. | 
| Endpoint.OS | string | Endpoint OS. | 

#### Human Readable Output

### Tenable.sc Device

|IP| UUID | MacAddress|
|---|---|---|
| {IP} | {UUID} | {MacAddress} |

### tenable-sc-list-users

***
List users in Tenable.sc. Results may vary based on the role type (admin or security manager).

#### Base Command

`tenable-sc-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Filter by user ID. | Optional | 
| username | Filter by user username. | Optional | 
| email | Filter by user email address. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.User.ID | string | User ID. | 
| TenableSC.User.Username | string | Username. | 
| TenableSC.User.FirstName | string | User first name. | 
| TenableSC.User.LastName | string | User last name. | 
| TenableSC.User.Title | string | User title. | 
| TenableSC.User.Email | string | User email address. | 
| TenableSC.User.Created | date | The creation time of the user. | 
| TenableSC.User.Modified | date | Last modification time of the user. | 
| TenableSC.User.Login | date | User last login. | 
| TenableSC.User.Role | string | User role name. | 

#### Human Readable Output

### Tenable.sc Users

|ID|Username|Title|Email|Created|Modified|LastLogin|Role|
|---|---|---|---|---|---|---|---|
| 1 | test |  |  | 2023-01-09T13:13:53Z | 2023-05-24T10:23:29Z |  | Security Manager |
| 2 | secman |  |  | 2023-02-06T09:54:47Z | 2023-05-01T10:05:46Z | 2023-05-24T12:43:35Z | Security Manager |

### tenable-sc-get-system-licensing

***
Retrieve licensing information from Tenable.sc. Requires admin role.

#### Base Command

`tenable-sc-get-system-licensing`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Status.ActiveIPS | number | Number of active IP addresses. | 
| TenableSC.Status.LicensedIPS | Unknown | Number of licensed IP addresses. | 
| TenableSC.Status.License | Unknown | License status. | 

#### Human Readable Output

### Tenable.sc Licensing information

|License|LicensedIPS|ActiveIPS|
|---|---|---|
| Valid | 512 | 152 |

### tenable-sc-get-system-information

***
Get the system information and diagnostics from Tenable.sc. Requires admin role.

#### Base Command

`tenable-sc-get-system-information`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.System.Version | string | System version. | 
| TenableSC.System.BuildID | string | System build ID. | 
| TenableSC.System.ReleaseID | string | System release ID. | 
| TenableSC.System.License | string | System license status. | 
| TenableSC.System.JavaStatus | boolean | Server Java status. | 
| TenableSC.System.RPMStatus | boolean | Server RPM status. | 
| TenableSC.System.DiskStatus | boolean | Server disk status. | 
| TenableSC.System.DiskThreshold | number | Disk threshold. | 
| TenableSC.System.LastCheck | date | System last check time. | 

#### Human Readable Output

### Tenable.sc System information

|RPMStatus|JavaStatus|DiskStatus|DiskThreshold|LastCheck|
|---|---|---|---|---|
| true | true | true | 5% | 2023-05-24T04:10:02Z |

### tenable-sc-get-all-scan-results

***
Returns all scan results in Tenable.sc. Requires security manager role.

#### Base Command

`tenable-sc-get-all-scan-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| manageable | Filter only manageable alerts. By default, returns both usable and manageable alerts. Possible values are: true, false. Default is false. | Optional | 
| page | The page to return, starting from 0. Default is 0. | Optional | 
| limit | The number of objects to return in one response (maximum limit is 200). Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanResults.ID | Number | Scan ID. | 
| TenableSC.ScanResults.Name | string | Scan name. | 
| TenableSC.ScanResults.Status | string | Scan status. | 
| TenableSC.ScanResults.Description | string | Scan description. | 
| TenableSC.ScanResults.Policy | string | Scan policy. | 
| TenableSC.ScanResults.Group | string | Scan group name. | 
| TenableSC.ScanResults.Checks | number | Scan completed number of checks. | 
| TenableSC.ScanResults.StartTime | date | Scan results start time. | 
| TenableSC.ScanResults.EndTime | date | Scan results end time. | 
| TenableSC.ScanResults.Duration | number | Scan duration in minutes. | 
| TenableSC.ScanResults.ImportTime | date | Scan import time. | 
| TenableSC.ScanResults.ScannedIPs | number | Number of scanned IPs. | 
| TenableSC.ScanResults.Owner | string | Scan owner name. | 
| TenableSC.ScanResults.RepositoryName | string | Scan repository name. | 
| TenableSC.ScanResults.ImportStatus | string | Scan import status. | 

#### Human Readable Output

### Tenable.sc Scan results - 0-1

Total number of elements is 77
|ID|Name|Status|Description|Policy|Group|Owner|ScannedIPs|StartTime|EndTime|Duration|Checks|ImportTime|RepositoryName|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 92 | test_scan_2023-mart-05-1950 | Error | Test scan 2023 | Network Scan | Full Access | secman | 0 | 2023-04-24T23:50:07Z | 2023-04-25T01:10:13Z | 80.1 | 22639720 |  | Local |
| 93 | test_scan_2023-mart-05-1950 | Error | Test scan 2023 | Network Scan | Full Access | secman | 0 | 2023-04-25T23:50:07Z | 2023-04-26T00:30:44Z | 40.61666666666667 | 12624659 |  | Local |

### tenable-sc-list-groups

***
List all groups. Requires security manager role.

#### Base Command

`tenable-sc-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| show_users | Whether to show group member. Possible values are: true, false. Default is true. | Optional | 
| limit | The number of objects to return in one response. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Group.Name | string | Group name. | 
| TenableSC.Group.ID | number | Group ID. | 
| TenableSC.Group.Description | string | Group description. | 
| TenableSC.Group.Users.Firstname | string | Group's user's first name. | 
| TenableSC.Group.Users.Lastname | string | Group's user's last name. | 
| TenableSC.Group.Users.ID | string | Group's user's ID. | 
| TenableSC.Group.Users.UUID | string | Group's user's UUID. | 
| TenableSC.Group.Users.Username | string | Group's user's username. | 

#### Human Readable Output

## Tenable.sc groups

|ID|
|---|
| 0 |

### Group id:0

|Username|Firstname|Lastname|
|---|---|---|
| test | test |  |
| secman |  |  |
| testuser1 | fname | lname |
| testuser444 | fname2 | lname2 |
| testuser3 | fname3 | lname3 |

### tenable-sc-create-user

***
Creates a new user. This command can be executed with both roles (admin or security manager) based on the role_id you choose.

#### Base Command

`tenable-sc-create-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | The user's first name. | Optional | 
| last_name | The user's last name. | Optional | 
| user_name | The user's username. | Required | 
| email | The user's email address. Required if email_notice is given. | Optional | 
| address | The user's postal address. | Optional | 
| phone | The user's phone number. | Optional | 
| city | The city the user is living in. | Optional | 
| state | The state the user is living in. | Optional | 
| country | The country the user is living in. | Optional | 
| locked | Whether the user should be locked. Possible values are: true, false. Default is false. | Optional | 
| email_notice | If different from None, a valid email address must be given. Possible values are: both, password, id, none. Default is none. | Optional | 
| auth_type | The authentication type. Tenable (TNS). Lightweight Directory Access Protocol (LDAP). Security Assertion Markup Language (SAML). LDAP server or SAML authentication needs to be configured in order to select LDAP or SAML. Possible values are: ldap, legacy, linked, saml, tns. Default is tns. | Required | 
| password | The user's password. Must be at least 3 characters. | Required | 
| time_zone | The user timezone, possible values can be found here: https://docs.oracle.com/middleware/1221/wcs/tag-ref/MISC/TimeZones.html. | Optional | 
| role_id | The user's role. Only an Administrator can create Administrator accounts. Possible values are: Administrator, Security Manager, Security Analyst, Vulnerability Analyst, Executive, Credential Manager, Auditor. | Required | 
| must_change_password | Whether the password must be changed. When choosing LDAP or SAML auth types, 'must_change_password' must be set to False. For all other cases can be either True or False. Possible values are: false, true. Default is false. | Optional | 
| managed_users_groups | Comma-separated list of session user's role that can manage groups. Use tenable-sc-list-groups to get all available groups. | Optional | 
| managed_objects_groups | Comma-separated list of the session user's role that can manage groups. Use tenable-sc-list-groups to get all available groups. | Optional | 
| group_id | Valid group ID whose users can be managed by the created user. | Required | 
| responsible_asset_id | Default is 0. ID of a valid, usable, accessible asset. Use tenable-sc-list-assets to get all available assets. -1 is not set, 0 is all assets, and other numbers are asset ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.User.Address | String | User address. | 
| TenableSC.User.ApiKeys | Unknown | User API keys. | 
| TenableSC.User.AuthType | String | User auth type. | 
| TenableSC.User.CanManage | Boolean | Whether the user has manage permissions. | 
| TenableSC.User.CanUse | Boolean | Whether the user has use permissions. | 
| TenableSC.User.City | String | User city of residence. | 
| TenableSC.User.Country | String | User country of residence. | 
| TenableSC.User.CreatedTime | Date | User creation time. | 
| TenableSC.User.Email | String | User email address. | 
| TenableSC.User.FailedLogins | String | Number of failed user logins. | 
| TenableSC.User.Fax | String | User fax. | 
| TenableSC.User.Fingerprint | Unknown | User fingerprint. | 
| TenableSC.User.Firstname | String | User first name. | 
| TenableSC.User.group.Description | String | User group's description. | 
| TenableSC.User.Group.ID | String | User group's ID. | 
| TenableSC.User.Group.Name | String | User group's name. | 
| TenableSC.User.ID | String | User ID. | 
| TenableSC.User.LastLogin | String | User last login time. | 
| TenableSC.User.LastLoginIP | String | User last login IP. | 
| TenableSC.User.Lastname | String | User last name. | 
| TenableSC.User.Ldap.Description | String | User LDAP description. | 
| TenableSC.User.Ldap.ID | Number | User LDAP ID. | 
| TenableSC.User.Ldap.Name | String | User LDAP name. | 
| TenableSC.User.LdapUsername | String | user LDAP username. | 
| TenableSC.User.Locked | String | Whether user is locked. | 
| TenableSC.User.ManagedObjectsGroups.Description | String | User managed object groups description. | 
| TenableSC.User.ManagedObjectsGroups.ID | String | User managed object groups ID. | 
| TenableSC.User.ManagedObjectsGroups.Name | String | User managed object groups name. | 
| TenableSC.User.ManagedUsersGroups.Description | String | User managed users groups description. | 
| TenableSC.User.ManagedUsersGroups.ID | String | User managed users groups ID. | 
| TenableSC.User.ManagedUsersGroups.Name | String | User managed users groups name. | 
| TenableSC.User.ModifiedTime | Date | User last modification time. | 
| TenableSC.User.MustChangePassword | String | If user must change password. | 
| TenableSC.User.Password | String | If user password is set. | 
| TenableSC.User.Phone | String | User phone number. | 
| TenableSC.User.Preferences.Name | String | User preferences name. | 
| TenableSC.User.Preferences.Tag | String | User preferences tag. | 
| TenableSC.User.Preferences.Value | String | User preferences value. | 
| TenableSC.User.ResponsibleAsset.Description | String | User responsible asset description. | 
| TenableSC.User.ResponsibleAsset.ID | String | User responsible asset ID. | 
| TenableSC.User.ResponsibleAsset.Name | String | User responsible asset name. | 
| TenableSC.User.ResponsibleAsset.UUID | Unknown | User responsible asset UUID. | 
| TenableSC.User.Role.Description | String | User role description. | 
| TenableSC.User.Role.ID | String | User role ID. | 
| TenableSC.User.Role.Name | String | User role name. | 
| TenableSC.User.State | String | User state. | 
| TenableSC.User.Status | String | User status. | 
| TenableSC.User.Title | String | User title. | 
| TenableSC.User.Username | String | User username. | 
| TenableSC.User.UUID | String | User UUID. | 

#### Human Readable Output

### User example_output was created successfully.

|User type|User Id|User Status|User Name|User Role Name|User Group Name|
|---|---|---|---|---|---|
| regular | 57 | 0 | example_output | Security Analyst | Full Access |

### tenable-sc-update-user

***
Update user details of the given user_id.

#### Base Command

`tenable-sc-update-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| first_name | The user's first name. | Optional | 
| last_name | The user's last name. | Optional | 
| user_name | The user's username. | Optional | 
| email | The user's email address. Required if email_notice is given. | Optional | 
| address | The user's postal address. | Optional | 
| phone | The user's phone number. | Optional | 
| city | The city the user is living in. | Optional | 
| state | The state the user is living in. | Optional | 
| country | The country the user is living in. | Optional | 
| locked | Whether the user should be locked. Possible values are: true, false. Default is false. | Optional | 
| time_zone | The user timezone. Possible values can be found here: https://docs.oracle.com/middleware/1221/wcs/tag-ref/MISC/TimeZones.html. | Optional | 
| role_id | The user's role. Only an Administrator can create Administrator accounts. Possible values are: Administrator, Security Manager, Security Analyst, Vulnerability Analyst, Executive, Credential Manager, Auditor. | Optional | 
| must_change_password | Whether the password must be changed. When choosing LDAP or SAML auth types, 'must_change_password' must be set to False. For all other cases can be either True or False. Possible values are: false, true. Default is false. | Optional | 
| managed_users_groups | Comma-separated list of session user's role that can manage groups. Use tenable-sc-list-groups to get all available groups. | Optional | 
| managed_objects_groups | Comma-separated list of session user's role that  can manage groups. Use tenable-sc-list-groups to get all available groups. | Optional | 
| group_id | Valid group ID whose users can be managed by the created user. | Optional | 
| responsible_asset_id | ID of a valid, usable, accessible asset. Use tenable-sc-list-assets to get all available assets. -1 is not set, 0 is all assets, and other numbers are asset ID. | Optional | 
| password | The new password to set. Must be given with current_password. Must be at least 3 characters. | Optional | 
| current_password | This is the admin/Security Manager password from the instance parameters. Required when attempting to change a user's password. | Optional | 
| user_id | The ID of the user whose details you want to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.User.Address | String | User address. | 
| TenableSC.User.ApiKeys | Unknown | User API keys. | 
| TenableSC.User.AuthType | String | User auth type. | 
| TenableSC.User.CanManage | Boolean | Whether the user has manage permissions. | 
| TenableSC.User.CanUse | Boolean | Whether the user has use permissions. | 
| TenableSC.User.City | String | User city of residence. | 
| TenableSC.User.Country | String | User country of residence. | 
| TenableSC.User.CreatedTime | Date | User creation time. | 
| TenableSC.User.Email | String | User email address. | 
| TenableSC.User.FailedLogins | String | Number of failed user logins. | 
| TenableSC.User.Fax | String | User fax. | 
| TenableSC.User.Fingerprint | Unknown | User fingerprint. | 
| TenableSC.User.Firstname | String | User first name. | 
| TenableSC.User.group.Description | String | User group's description. | 
| TenableSC.User.Group.ID | String | User group's ID. | 
| TenableSC.User.Group.Name | String | User group's name. | 
| TenableSC.User.ID | String | User ID. | 
| TenableSC.User.LastLogin | String | User last login time. | 
| TenableSC.User.LastLoginIP | String | User last login IP. | 
| TenableSC.User.Lastname | String | User last name. | 
| TenableSC.User.Ldap.Description | String | User LDAP description. | 
| TenableSC.User.Ldap.ID | Number | User LDAP ID. | 
| TenableSC.User.Ldap.Name | String | User LDAP name. | 
| TenableSC.User.LdapUsername | String | User LDAP username. | 
| TenableSC.User.Locked | String | Whether user is locked. | 
| TenableSC.User.ManagedObjectsGroups.Description | String | User managed object groups description. | 
| TenableSC.User.ManagedObjectsGroups.ID | String | User managed object groups ID. | 
| TenableSC.User.ManagedObjectsGroups.Name | String | User managed object groups name. | 
| TenableSC.User.ManagedUsersGroups.Description | String | User managed users groups description. | 
| TenableSC.User.ManagedUsersGroups.ID | String | User managed users groups ID. | 
| TenableSC.User.ManagedUsersGroups.Name | String | User managed users groups name. | 
| TenableSC.User.ModifiedTime | Date | User last modification time. | 
| TenableSC.User.MustChangePassword | String | If user must change password. | 
| TenableSC.User.Password | String | If user password is set. | 
| TenableSC.User.Phone | String | User phone number. | 
| TenableSC.User.Preferences.Name | String | User preferences name. | 
| TenableSC.User.Preferences.Tag | String | User preferences tag. | 
| TenableSC.User.Preferences.Value | String | User preferences value. | 
| TenableSC.User.ResponsibleAsset.Description | String | User responsible asset description. | 
| TenableSC.User.ResponsibleAsset.ID | String | User responsible asset ID. | 
| TenableSC.User.ResponsibleAsset.Name | String | User responsible asset name. | 
| TenableSC.User.ResponsibleAsset.UUID | Unknown | User responsible asset UUID. | 
| TenableSC.User.Role.Description | String | User role description. | 
| TenableSC.User.Role.ID | String | User role ID. | 
| TenableSC.User.Role.Name | String | User role name. | 
| TenableSC.User.State | String | User state. | 
| TenableSC.User.Status | String | User status. | 
| TenableSC.User.Title | String | User title. | 
| TenableSC.User.Username | String | User username. | 
| TenableSC.User.UUID | String | User UUID. | 

#### Human Readable Output

### user 23 was updated successfully.

|User type|User Id|User Status|User Name|First Name|Lat Name |Email |User Role Name|User Group Name|
|---|---|---|---|---|---|---|---|---|
| regular | 23 | 0 | testuser30 | testuser30 | testuser30 | <testuser30@mymail.com> | Credential Manager | Full Access |

### tenable-sc-delete-user

***
Delete a user by given user_id. This command can be executed with both roles (admin or security manager).

#### Base Command

`tenable-sc-delete-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The ID of the user we want to delete. | Required | 

#### Context Output

There is no context output for this command.

#### Human Readable Output

User {user_id} was deleted successfully.

### tenable-sc-list-plugin-family

***
List plugin families / return information about a plugin family given ID. Requires security manager role.

#### Base Command

`tenable-sc-list-plugin-family`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| plugin_id | The ID of the plugin to search. If given, other arguments will be ignored. | Optional | 
| limit | The number of objects to return in one response (maximum limit is 200). Ignored when plugin_id is given. Default is 50. | Optional | 
| is_active | Default is none. none - both active and passive Plugin Families are returned. true - Only active Plugin Families will be returned. false - Only passive Plugin Families will be returned. Ignored when plugin_id is given. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.PluginFamily.ID | String | Plugin family ID. | 
| TenableSC.PluginFamily.Name | String | Plugin family name. | 
| TenableSC.PluginFamily.Count | String | Number of plugins in a family. | 
| TenableSC.PluginFamily.Plugins | String | The plugins list. | 
| TenableSC.PluginFamily.Type | String | Plugin family type. | 

#### Human Readable Output

When plugin_id isn't given:

### Plugin families:

|Plugin ID|Plugin Name|
|---|---|
| 0 | N/A |
| 1 | Red Hat Local Security Checks |

When plugin_id is given:

### Plugin families:

|Plugin ID|Plugin Name|Is Active|
|---|---|---|
| 2 | HP-UX Local Security Checks | true |

### tenable-sc-create-policy

***
Creates a policy. Requires security manager role. This command is prerequisite for creating remediation scan.

#### Base Command

`tenable-sc-create-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the policy to create. | Optional | 
| policy_description | The description of the policy to create. | Optional | 
| policy_template_id | Policy template id. Default is 1. Default is 1. | Required | 
| port_scan_range | Possible values: default, all or a comma-separated list of values - 21,23,25,80,110. | Optional | 
| tcp_scanner | Only possible if you are using Linux or FreeBSD. On Windows or macOS, the scanner does not do a TCP scan and instead uses the SYN scanner. If you enable this option, you can also set the syn_firewall_detection option. Possible values are: no, yes. Default is no. | Optional | 
| syn_scanner | Identifies open TCP ports on the target hosts. If you enable this option, you can also set the syn_firewall_detection option. Possible values are: no, yes. Default is yes. | Optional | 
| udp_scanner | Enabling the UDP port scanner may dramatically increase the scan time and produce unreliable results. Consider using the netstat or SNMP port enumeration options instead if possible. Possible values are: no, yes. Default is no. | Optional | 
| family_id | Family ID. Can be retrieved from the result of the tenable-sc-list-plugin-family command. | Required | 
| plugins_id | Comma-separated list of plugin_ids, Can be retrieved from the result of  the tenable-sc-list-plugin-family command  with family_id as the argument. | Required | 
| syn_firewall_detection | Rely on local port enumeration first before relying on network port scans. Possible values are: Automatic (normal), Do not detect RST rate limitation(soft), Ignore closed ports(aggressive), Disabled(softer). Default is Automatic (normal). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanPolicy.AuditFiles | Unknown | Policy audit files. | 
| TenableSC.ScanPolicy.CanManage | String | Policy permissions. | 
| TenableSC.ScanPolicy.CanUse | String | Policy permissions. | 
| TenableSC.ScanPolicy.Context | String | Policy context. | 
| TenableSC.ScanPolicy.CreatedTime | Date | Policy creation time. | 
| TenableSC.ScanPolicy.Creator.Firstname | String | Policy creator first name. | 
| TenableSC.ScanPolicy.Creator.ID | String | Policy creator ID. | 
| TenableSC.ScanPolicy.Creator.Lastname | String | Policy creator last name. | 
| TenableSC.ScanPolicy.Creator.Username | String | Policy creator user name. | 
| TenableSC.ScanPolicy.Creator.UUID | String | Policy creator UUID. | 
| TenableSC.ScanPolicy.Description | String | Policy description. | 
| TenableSC.ScanPolicy.Families.Count | String | Policy number of families. | 
| TenableSC.ScanPolicy.Families.ID | String | Policy family ID. | 
| TenableSC.ScanPolicy.Families.Name | String | Policy family name. | 
| TenableSC.ScanPolicy.Families.Plugins | Unknown | Policy family plugins. | 
| TenableSC.ScanPolicy.GenerateXCCDFResults | String | Policy generated XCCDF results. | 
| TenableSC.ScanPolicy.Groups | Unknown | Policy groups. | 
| TenableSC.ScanPolicy.ID | String | Policy ID. | 
| TenableSC.ScanPolicy.ModifiedTime | Date | Policy last modification time. | 
| TenableSC.ScanPolicy.Name | String | Policy name. | 
| TenableSC.ScanPolicy.Owner.Firstname | String | Policy owner first name. | 
| TenableSC.ScanPolicy.Owner.ID | String | Policy owner ID. | 
| TenableSC.ScanPolicy.Owner.Lastname | String | Policy owner last name. | 
| TenableSC.ScanPolicy.Owner.Username | String | Policy owner username. | 
| TenableSC.ScanPolicy.Owner.UUID | String | Policy owner UUID. | 
| TenableSC.ScanPolicy.OwnerGroup.Description | String | Policy owner group description. | 
| TenableSC.ScanPolicy.OwnerGroup.ID | String | Policy owner group ID. | 
| TenableSC.ScanPolicy.OwnerGroup.Name | String | Policy owner group name. | 
| TenableSC.ScanPolicy.PolicyTemplate.Agent | String | Policy template agent. | 
| TenableSC.ScanPolicy.PolicyTemplate.Description | String | Policy template description. | 
| TenableSC.ScanPolicy.PolicyTemplate.ID | String | Policy template ID. | 
| TenableSC.ScanPolicy.PolicyTemplate.Name | String | Policy template name. | 
| TenableSC.ScanPolicy.Preferences.PortscanRange | String | Policy port scan range. | 
| TenableSC.ScanPolicy.Preferences.SynFirewallDetection | String | Policy SYN firewall detection. | 
| TenableSC.ScanPolicy.Preferences.SynScanner | String | Policy SYN scanner. | 
| TenableSC.ScanPolicy.Preferences.TcpScanner | String | Policy TCP scanner. | 
| TenableSC.ScanPolicy.Preferences.UdpScanner | String | Policy UDP scanner. | 
| TenableSC.ScanPolicy.Status | String | Policy status. | 
| TenableSC.ScanPolicy.tags | String | Policy tags. | 
| TenableSC.ScanPolicy.TargetGroup.Description | String | Policy target group description. | 
| TenableSC.ScanPolicy.TargetGroup.ID | Number | Policy target group ID. | 
| TenableSC.ScanPolicy.TargetGroup.Name | String | Policy target group name. | 
| TenableSC.ScanPolicy.UUID | String | Policy UUID. | 

#### Human Readable Output

### Policy was created successfully:

|Policy type|name|Created Time|Plugin Families|Policy  Status|Policy UUID|Policy can Manage|Creator Username|policyTemplate Name|
|---|---|---|---|---|---|---|---|---|
| regular | scan_name | 1684923394 | {'id': '1', 'name': 'Red Hat Local Security Checks', 'count': '9297', 'plugins': []} | 0 | {policy UUID} | true | yuv | Advanced Scan |

### tenable-sc-list-query

***
Lists the queries. Requires security manager role.

#### Base Command

`tenable-sc-list-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The ID of the query to search. | Optional | 
| type | The query type to retrieve. When no type is set all queries are returned. Possible values are: alert, lce, mobile, ticket, user. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Query.Manageable.BrowseColumns | String | Relevant only when query_id is not given. Manageable Query browse columns. | 
| TenableSC.Query.Manageable.BrowseSortColumn | String | Relevant only when query_id is not given. Manageable Query browse sort column. | 
| TenableSC.Query.Manageable.BrowseSortDirection | String | Relevant only when query_id is not given. Manageable Query browse sort direction. | 
| TenableSC.Query.Manageable.CanManage | String | Relevant only when query_id is not given. Manageable Query permissions. | 
| TenableSC.Query.Manageable.CanUse | String | Relevant only when query_id is not given. Manageable Query permissions. | 
| TenableSC.Query.Manageable.Context | String | Relevant only when query_id is not given. Manageable Query context. | 
| TenableSC.Query.Manageable.CreatedTime | Date | Relevant only when query_id is not given. Manageable Query creation time. | 
| TenableSC.Query.Manageable.Creator.Firstname | String | Relevant only when query_id is not given. Manageable Query Creator first name. | 
| TenableSC.Query.Manageable.Creator.ID | String | Relevant only when query_id is not given. Manageable Query Creator ID. | 
| TenableSC.Query.Manageable.Creator.Lastname | String | Relevant only when query_id is not given. Manageable Query Creator last name. | 
| TenableSC.Query.Manageable.Creator.Username | String | Relevant only when query_id is not given. Manageable Query Creator user name. | 
| TenableSC.Query.Manageable.Creator.UUID | String | Relevant only when query_id is not given. Manageable Query Creator UUID. | 
| TenableSC.Query.Manageable.Description | String | Relevant only when query_id is not given. Manageable Query description. | 
| TenableSC.Query.Manageable.Filters.FilterName | String | Relevant only when query_id is not given. Manageable Query filter name. | 
| TenableSC.Query.Manageable.Filters.Operator | String | Relevant only when query_id is not given. Manageable Query filter operator. | 
| TenableSC.Query.Manageable.Filters.Value | String | Relevant only when query_id is not given. Manageable Query filter value | 
| TenableSC.Query.Manageable.Groups | Unknown | Relevant only when query_id is not given. Manageable Query groups. | 
| TenableSC.Query.Manageable.ID | String | Relevant only when query_id is not given. Manageable Query ID. | 
| TenableSC.Query.Manageable.ModifiedTime | Date | Relevant only when query_id is not given. Manageable Query modification time. | 
| TenableSC.Query.Manageable.Name | String | Relevant only when query_id is not given. Manageable Query name. | 
| TenableSC.Query.Manageable.Owner.Firstname | String | Relevant only when query_id is not given. Manageable Query owner first name. | 
| TenableSC.Query.Manageable.Owner.ID | String | Relevant only when query_id is not given. Manageable Query owner ID. | 
| TenableSC.Query.Manageable.Owner.Lastname | String | Relevant only when query_id is not given. Manageable Query owner last name. | 
| TenableSC.Query.Manageable.Owner.Username | String | Relevant only when query_id is not given. Manageable Query owner user name. | 
| TenableSC.Query.Manageable.Owner.UUID | String | Relevant only when query_id is not given. Manageable Query owner UUID. | 
| TenableSC.Query.Manageable.OwnerGroup.Description | String | Relevant only when query_id is not given. Manageable Query owner group description. | 
| TenableSC.Query.Manageable.OwnerGroup.ID | String | Relevant only when query_id is not given. Manageable Query owner group ID. | 
| TenableSC.Query.Manageable.OwnerGroup.Name | String | Relevant only when query_id is not given. Manageable Query owner group name. | 
| TenableSC.Query.Manageable.Status | String | Relevant only when query_id is not given. Manageable Query status. | 
| TenableSC.Query.Manageable.Tags | String | Relevant only when query_id is not given. Manageable Query tags. | 
| TenableSC.Query.Manageable.TargetGroup.Description | String | Relevant only when query_id is not given. Manageable Query target group description. | 
| TenableSC.Query.Manageable.TargetGroup.ID | Number | Relevant only when query_id is not given. Manageable Query target group ID. | 
| TenableSC.Query.Manageable.TargetGroup.Name | String | Relevant only when query_id is not given. Manageable Query target group name. | 
| TenableSC.Query.Manageable.Tool | String | Relevant only when query_id is not given. Manageable Query tool. | 
| TenableSC.Query.Manageable.Type | String | Relevant only when query_id is not given. Manageable Query type. | 
| TenableSC.Query.Manageable.Filters.Value.Description | String | Relevant only when query_id is not given. Manageable Query filter value description. | 
| TenableSC.Query.Manageable.Filters.Value.ID | String | Relevant only when query_id is not given. Manageable Query filter value ID. | 
| TenableSC.Query.Manageable.Filters.Value.Name | String | Relevant only when query_id is not given. Manageable Query filter value name. | 
| TenableSC.Query.Manageable.Filters.Value.Type | String | Relevant only when query_id is not given. Manageable Query filter value type. | 
| TenableSC.Query.Manageable.Filters.Value.UUID | String | Relevant only when query_id is not given. Manageable Query filter value UUID | 
| TenableSC.Query.Manageable.Filters | Unknown | Relevant only when query_id is not given. Manageable Query filters. | 
| TenableSC.Query.Usable.BrowseColumns | String | Relevant only when query_id is not given. Usable Query browse columns. | 
| TenableSC.Query.Usable.BrowseSortColumn | String | Relevant only when query_id is not given. Usable Query browse sort column. | 
| TenableSC.Query.Usable.BrowseSortDirection | String | Relevant only when query_id is not given. Usable Query browse sort direction. | 
| TenableSC.Query.Usable.CanManage | String | Relevant only when query_id is not given. Usable Query permissions. | 
| TenableSC.Query.Usable.CanUse | String | Relevant only when query_id is not given. Usable Query permissions. | 
| TenableSC.Query.Usable.Context | String | Relevant only when query_id is not given. Usable Query context. | 
| TenableSC.Query.Usable.CreatedTime | Date | Relevant only when query_id is not given. Usable Query creation time. | 
| TenableSC.Query.Usable.Creator.Firstname | String | Relevant only when query_id is not given. Usable Query Creator first name. | 
| TenableSC.Query.Usable.Creator.ID | String | Relevant only when query_id is not given. Usable Query Creator ID. | 
| TenableSC.Query.Usable.Creator.Lastname | String | Relevant only when query_id is not given. Usable Query Creator last name. | 
| TenableSC.Query.Usable.Creator.Username | String | Relevant only when query_id is not given. Usable Query Creator user name. | 
| TenableSC.Query.Usable.Creator.UUID | String | Relevant only when query_id is not given. Usable Query Creator UUID. | 
| TenableSC.Query.Usable.Description | String | Relevant only when query_id is not given. Usable Query description. | 
| TenableSC.Query.Usable.Filters.FilterName | String | Relevant only when query_id is not given. Usable Query filter name. | 
| TenableSC.Query.Usable.Filters.Operator | String | Relevant only when query_id is not given. Usable Query filter operator. | 
| TenableSC.Query.Usable.Filters.Value | String | Relevant only when query_id is not given. Usable Query filter value. | 
| TenableSC.Query.Usable.Groups | Unknown | Relevant only when query_id is not given. Usable Query groups. | 
| TenableSC.Query.Usable.ID | String | Relevant only when query_id is not given. Usable Query ID. | 
| TenableSC.Query.Usable.ModifiedTime | Date | Relevant only when query_id is not given. Usable Query modification time. | 
| TenableSC.Query.Usable.Name | String | Relevant only when query_id is not given. Usable Query name. | 
| TenableSC.Query.Usable.Owner.Firstname | String | Relevant only when query_id is not given. Usable Query owner first name. | 
| TenableSC.Query.Usable.Owner.ID | String | Relevant only when query_id is not given. Usable Query owner ID. | 
| TenableSC.Query.Usable.Owner.Lastname | String | Relevant only when query_id is not given. Usable Query owner last name. | 
| TenableSC.Query.Usable.Owner.Username | String | Relevant only when query_id is not given. Usable Query owner user name. | 
| TenableSC.Query.Usable.Owner.UUID | String | Relevant only when query_id is not given. Usable Query owner UUID. | 
| TenableSC.Query.Usable.OwnerGroup.Description | String | Relevant only when query_id is not given. Usable Query owner group description. | 
| TenableSC.Query.Usable.OwnerGroup.ID | String | Relevant only when query_id is not given. Usable Query owner group ID. | 
| TenableSC.Query.Usable.OwnerGroup.Name | String | Relevant only when query_id is not given. Usable Query owner group name. | 
| TenableSC.Query.Usable.Status | String | Relevant only when query_id is not given. Usable Query status. | 
| TenableSC.Query.Usable.Tags | String | Relevant only when query_id is not given. Usable Query tags. | 
| TenableSC.Query.Usable.TargetGroup.Description | String | Relevant only when query_id is not given. Usable Query target group description. | 
| TenableSC.Query.Usable.TargetGroup.ID | Number | Relevant only when query_id is not given. Usable Query target group ID. | 
| TenableSC.Query.Usable.TargetGroup.Name | String | Relevant only when query_id is not given. Usable Query target group name. | 
| TenableSC.Query.Usable.Tool | String | Relevant only when query_id is not given. Usable Query tool. | 
| TenableSC.Query.Usable.Type | String | Relevant only when query_id is not given. Usable Query type. | 
| TenableSC.Query.Usable.Filters.Value.Description | String | Relevant only when query_id is not given. Usable Query filter value description. | 
| TenableSC.Query.Usable.Filters.Value.ID | String | Relevant only when query_id is not given. Usable Query filter value ID. | 
| TenableSC.Query.Usable.Filters.Value.Name | String | Relevant only when query_id is not given. Usable Query filter value name. | 
| TenableSC.Query.Usable.Filters.Value.Type | String | Relevant only when query_id is not given. Usable Query filter value type. | 
| TenableSC.Query.Usable.Filters.Value.UUID | String | Relevant only when query_id is not given. Usable Query filter value UUID. | 
| TenableSC.Query.Usable.Filters | Unknown | Relevant only when query_id is not given. Usable Query filters. | 
| TenableSC.Query.BrowseColumns | String | Relevant only when query_id is given. Query browse columns. | 
| TenableSC.Query.BrowseSortColumn | String | Relevant only when query_id is given. Query browse sort columns. | 
| TenableSC.Query.BrowseSortDirection | String | Relevant only when query_id is given. Query browse sort direction | 
| TenableSC.Query.CanManage | String | Relevant only when query_id is given. Query permissions. | 
| TenableSC.Query.CanUse | String | Relevant only when query_id is given. Query permissions. | 
| TenableSC.Query.Context | String | Relevant only when query_id is given. Query context. | 
| TenableSC.Query.CreatedTime | Date | Relevant only when query_id is given. Query creation time. | 
| TenableSC.Query.Creator.Firstname | String | Relevant only when query_id is given. Query creator first name. | 
| TenableSC.Query.Creator.ID | String | Relevant only when query_id is given. Query creator ID. | 
| TenableSC.Query.Creator.Lastname | String | Relevant only when query_id is given. Query creator last name. | 
| TenableSC.Query.Creator.Username | String | Relevant only when query_id is given. Query creator user name. | 
| TenableSC.Query.Creator.UUID | String | Relevant only when query_id is given. Query creator UUID. | 
| TenableSC.Query.Description | String | Relevant only when query_id is given. Query description. | 
| TenableSC.Query.Filters | Unknown | Relevant only when query_id is given. Query filters. | 
| TenableSC.Query.Groups | Unknown | Relevant only when query_id is given. Query groups. | 
| TenableSC.Query.ID | String | Relevant only when query_id is given. Query ID. | 
| TenableSC.Query.ModifiedTime | Date | Relevant only when query_id is given. Query modification time. | 
| TenableSC.Query.Name | String | Relevant only when query_id is given. Query name. | 
| TenableSC.Query.Owner.Firstname | String | Relevant only when query_id is given. Query owner first name. | 
| TenableSC.Query.Owner.ID | String | Relevant only when query_id is given. Query owner ID. | 
| TenableSC.Query.Owner.Lastname | String | Relevant only when query_id is given. Query owner last name. | 
| TenableSC.Query.Owner.Username | String | Relevant only when query_id is given. Query owner user name. | 
| TenableSC.Query.Owner.UUID | String | Relevant only when query_id is given. Query owner UUID. | 
| TenableSC.Query.OwnerGroup.Description | String | Relevant only when query_id is given. Query owner group description. | 
| TenableSC.Query.OwnerGroup.ID | String | Relevant only when query_id is given. Query owner group ID. | 
| TenableSC.Query.OwnerGroup.Name | String | Relevant only when query_id is given. Query owner group name. | 
| TenableSC.Query.Status | String | Relevant only when query_id is given. Query status. | 
| TenableSC.Query.Tags | String | Relevant only when query_id is given. Query tags. | 
| TenableSC.Query.TargetGroup.Description | String | Relevant only when query_id is given. Query target group description. | 
| TenableSC.Query.TargetGroup.ID | Number | Relevant only when query_id is given. Query target group ID. | 
| TenableSC.Query.TargetGroup.Name | String | Relevant only when query_id is given. Query target group name. | 
| TenableSC.Query.Tool | String | Relevant only when query_id is given. Query tool | 
| TenableSC.Query.Type | String | Relevant only when query_id is given. Query type. | 

#### Human Readable Output

If query_id isn't given:

### Queries:

|Query Id|Query  Name|Query Description|Query Filters|Query Manageable|Query Usable|
|---|---|---|---|---|---|
| 1 | test_name | test_description | filter | True | True |
| 2 | test_name | test_description |  | True | False |

If query_id is given:

### Query {query_id}

|Query Id|Query  Name|Query Description|
|---|---|---|
| test_id | test_name | test_description |

### tenable-sc-update-asset

***
Requires security manager role. Update an asset.

#### Base Command

`tenable-sc-update-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Asset name. | Optional | 
| asset_id | The ID of the asset to update. | Required | 
| description | The asset description. | Optional | 
| owner_id | The asset owner ID. | Optional | 
| tag | The asset tag. | Optional | 
| ip_list | Comma-separated list of the asset IPs list. | Optional | 

#### Context Output

There is no context output for this command.

#### Human Readable Output

asset {asset_id} was updated successfully.

### tenable-sc-create-remediation-scan

***
Creates a remediation scan. Requires security manager role. This command is a prerequisite for creating remediation scan.

#### Base Command

`tenable-sc-create-remediation-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the policy to create. | Optional | 
| policy_description | The description of the policy to create. | Optional | 
| port_scan_range | Possible values: default, all or a comma-separated list of values - 21,23,25,80,110. | Optional | 
| tcp_scanner | Only possible if you are using Linux or FreeBSD. On Windows or macOS, the scanner does not do a TCP scan and instead uses the SYN scanner..If you enable this option, you can also set the syn_firewall_detection. Possible values are: no, yes. Default is no. | Optional | 
| syn_scanner | Identifies open TCP ports on the target hosts. If you enable this option, you can also set the syn_firewall_detection option. Possible values are: no, yes. Default is yes. | Optional | 
| udp_scanner | Enabling the UDP port scanner may dramatically increase the scan time and produce unreliable results. Consider using the netstat or SNMP port enumeration options instead if possible. Possible values are: no, yes. Default is no. | Optional | 
| syn_firewall_detection | Default is Automatic (normal). Rely on local port enumeration first before relying on network port scans. Possible values are: Automatic (normal), Do not detect RST rate limitation(soft), Ignore closed ports(aggressive), Disabled(softer). Default is Automatic (normal). | Optional | 
| family_id | Can be retrieved from the result of the tenable-sc-list-plugin-family command. | Required | 
| plugins_id | Comma-separated list of plugin_ids, Can be retrieved from the result of the tenable-sc-list-plugin-family command  with family_id as the argument. | Required | 
| scan_name | Scan name. | Required | 
| description | Scan description. | Optional | 
| repository_id | Scan Repository ID, can be retrieved from the list-repositories command. Default is 1. | Required | 
| time_zone | The timezone for the given start_time. Possible values can be found here: https://docs.oracle.com/middleware/1221/wcs/tag-ref/MISC/TimeZones.html. | Optional | 
| start_time | The scan start time, in the format of YYYY-MM-DD:HH:MM:SS or relative timestamp (i.e., now, 3 days). | Optional | 
| repeat_rule_freq | Specifies repeating events based on an interval of a repeat_rule_freq or more. Possible values are: HOURLY, DAILY, WEEKLY, MONTHLY, YEARLY. | Optional | 
| repeat_rule_interval | The number of repeat_rule_freq between each interval (for example: If repeat_rule_freq=DAILY and repeat_rule_interval=8 it means every eight days.). | Optional | 
| repeat_rule_by_day | A comma-separated list of days of the week to run the schedule. Possible values are: SU, MO, TU, WE, TH, FR, SA. | Optional | 
| asset_ids | Either no assets or comma-separated list of asset IDs to scan. Can be retrieved from the list-assets command. | Optional | 
| scan_virtual_hosts | Default is false. Whether to include virtual hosts. Possible values are: true, false. | Optional | 
| ip_list | Comma-separated IPs to scan, e.g., 10.0.0.1,10.0.0.2 . | Optional | 
| report_ids | Comma-separated list of report definition IDs to create post-scan. Can be retrieved from the list-report-definitions command. | Optional | 
| credentials | Comma-separated credentials IDs to use. Can be retrieved from the list-credentials command. | Optional | 
| timeout_action | discard - do not import any of the results obtained by the scan to the database. import - Import the results of the current scan and discard the information for any unscanned targets. rollover-Import the results from the scan into the database and create a rollover scan that may be launched at a later time to complete the scan. Possible values are: discard, import, rollover. Default is import. | Optional | 
| max_scan_time | Maximum scan run time in hours. Default is 1. | Optional | 
| dhcp_tracking | Track hosts which have been issued new IP address, (e.g., DHCP). Possible values are: true, false. | Optional | 
| enabled | Whether the schedule is enabled. The "enabled" field can only be set to "false" for schedules of type "ical". For all other schedules types, "enabled" is set to "true". Possible values are: true, false. Default is true. | Optional | 
| rollover_type | Create a rollover scan scheduled to launch the next day at the same start time as the just completed scan. template-Create a rollover scan as a template for users to launch manually This field is required if the timeout_action is set to rollover. Default is nextDay. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Scan.Assets | Unknown | Scan assets. | 
| TenableSC.Scan.CanManage | String | Scan permissions. | 
| TenableSC.Scan.CanUse | String | Scan permissions. | 
| TenableSC.Scan.ClassifyMitigatedAge | String | Scan classify mitigated age. | 
| TenableSC.Scan.CreatedTime | Date | Scan creation time. | 
| TenableSC.Scan.Creator.Firstname | String | Scan creator first name. | 
| TenableSC.Scan.Creator.ID | String | Scan creator ID. | 
| TenableSC.Scan.Creator.Lastname | String | Scan creator last name. | 
| TenableSC.Scan.Creator.Username | String | Scan creator username. | 
| TenableSC.Scan.Creator.UUID | String | Scan creator UUID. | 
| TenableSC.Scan.Credentials | Unknown | Scan credentials. | 
| TenableSC.Scan.Description | String | Scan description. | 
| TenableSC.Scan.DhcpTracking | String | Scan DHCP tracking. | 
| TenableSC.Scan.EmailOnFinish | String | Scan email on finish. | 
| TenableSC.Scan.EmailOnLaunch | String | Scan email on launch. | 
| TenableSC.Scan.ID | String | Scan ID. | 
| TenableSC.Scan.IpList | String | Scan IP list. | 
| TenableSC.Scan.MaxScanTime | String | Scan max scan time. | 
| TenableSC.Scan.ModifiedTime | Date | Scan last modification time. | 
| TenableSC.Scan.Name | String | Scan name. | 
| TenableSC.Scan.NumDependents | Number | Scan number of dependents. | 
| TenableSC.Scan.Owner.Firstname | String | Scan owner first name. | 
| TenableSC.Scan.Owner.ID | String | Scan owner ID. | 
| TenableSC.Scan.Owner.Lastname | String | Scan owner last name. | 
| TenableSC.Scan.Owner.Username | String | Scan owner username. | 
| TenableSC.Scan.Owner.UUID | String | Scan owner UUID. | 
| TenableSC.Scan.OwnerGroup.Description | String | Scan owner group description. | 
| TenableSC.Scan.OwnerGroup.ID | String | Scan owner group ID. | 
| TenableSC.Scan.OwnerGroup.Name | String | Scan owner group name. | 
| TenableSC.Scan.Plugin.Description | String | Scan plugin description. | 
| TenableSC.Scan.Plugin.ID | String | Scan plugin ID. | 
| TenableSC.Scan.Plugin.Name | String | Scan plugin name. | 
| TenableSC.Scan.Plugin.Type | String | Scan plugin type. | 
| TenableSC.Scan.Policy.Context | String | Scan policy context. | 
| TenableSC.Scan.Policy.Description | String | Scan policy description. | 
| TenableSC.Scan.Policy.ID | String | Scan policy ID. | 
| TenableSC.Scan.Policy.Name | String | Scan policy name. | 
| TenableSC.Scan.Policy.Owner.Firstname | String | Scan policy owner first name. | 
| TenableSC.Scan.Policy.Owner.ID | String | Scan policy owner ID. | 
| TenableSC.Scan.Policy.Owner.Lastname | String | Scan policy owner last name. | 
| TenableSC.Scan.Policy.Owner.Username | String | Scan policy owner username. | 
| TenableSC.Scan.Policy.Owner.UUID | String | Scan policy owner UUID. | 
| TenableSC.Scan.Policy.OwnerGroup.Description | String | Scan policy owner group description. | 
| TenableSC.Scan.Policy.OwnerGroup.ID | String | Scan policy owner group ID. | 
| TenableSC.Scan.Policy.OwnerGroup.Name | String | Scan policy owner group name. | 
| TenableSC.Scan.Policy.Tags | String | Scan policy tags. | 
| TenableSC.Scan.Policy.UUID | String | Scan policy UUID. | 
| TenableSC.Scan.PolicyPrefs.Name | String | Scan policy preferation name. | 
| TenableSC.Scan.PolicyPrefs.Value | String | Scan policy preferation value. | 
| TenableSC.Scan.Reports | Unknown | Scan reports. | 
| TenableSC.Scan.Repository.Description | String | Scan repository description. | 
| TenableSC.Scan.Repository.ID | String | Scan repository ID. | 
| TenableSC.Scan.Repository.Name | String | Scan repository name. | 
| TenableSC.Scan.Repository.Type | String | Scan repository type. | 
| TenableSC.Scan.Repository.UUID | String | Scan repository UUID. | 
| TenableSC.Scan.RolloverType | String | Scan rollover type. | 
| TenableSC.Scan.ScanResultID | String | Scan results ID. | 
| TenableSC.Scan.ScanningVirtualHosts | String | Scan virtual hosts. | 
| TenableSC.Scan.Schedule.Dependent.Description | String | Scan schedule dependent description. | 
| TenableSC.Scan.Schedule.Dependent.ID | Number | Scan schedule dependent ID. | 
| TenableSC.Scan.Schedule.Dependent.Name | String | Scan schedule dependent name. | 
| TenableSC.Scan.Schedule.Enabled | String | Scan schedule enabled. | 
| TenableSC.Scan.Schedule.ID | Number | Scan schedule ID. | 
| TenableSC.Scan.Schedule.NextRun | Number | Scan schedule next run. | 
| TenableSC.Scan.Schedule.ObjectType | Number | Scan schedule object type. | 
| TenableSC.Scan.Schedule.RepeatRule | String | Scan schedule repeat rule. | 
| TenableSC.Scan.Schedule.Start | String | Scan schedule start time. | 
| TenableSC.Scan.Schedule.Type | String | Scan schedule type. | 
| TenableSC.Scan.Status | String | Scan status. | 
| TenableSC.Scan.TimeoutAction | String | Scan timeout action. | 
| TenableSC.Scan.Type | String | Scan type. | 
| TenableSC.Scan.UUID | String | Scan UUID. | 
| TenableSC.Scan.Zone.Description | String | Scan zone description. | 
| TenableSC.Scan.Zone.ID | Number | Scan zone ID. | 
| TenableSC.Scan.Zone.Name | String | Scan zone name. | 

#### Human Readable Output

### Remediation scan created successfully

|Scan ID|Scan Name|Scan Type|Dhcp Tracking status|Created Time|Modified Time|Max Scan Time|Policy id |Policy context|Schedule type|Group|Owner|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 69 | my_Test_scan | policy | false | 2023-05-24T10:12:27Z | 1684923147 | 3600 | 1000044 | scan | now | Full Access | yuv |

### Vulnerabilities

|ID|Name|Family|Severity|Total|
|---|---|---|---|---|
| 10092 | FTP Server Detection | Service detection | Info | 6 |
| 10107 | HTTP Server Type and Version | Web Servers | Info | 61 |

## Troubleshooting

For errors within Tenable.sc, the cause is generally specified, e.g., The currently logged in used is not an administrator, Unable to retrieve Asset #2412. Asset #2412 does not exist or Invalid login credentials. However there might be connection errors, for example when the server URL provided is incorrect.

### tenable-sc-get-organization

***
Requires administrator role. Command to get a list of organizations' information, depending on the comma-separated list of fields provided.

#### Base Command

`tenable-sc-get-organization`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | Optional fields to return specific values, example: restrictedIPs. | Optional | 

#### Context Output

There is no context output for this command.