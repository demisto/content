With Tenable.sc (formerly SecurityCenter) you get a real-time, continuous assessment of your security posture so you can find and fix vulnerabilities faster.
This integration was integrated and tested with version xx of Tenable.sc

## Configure Tenable.sc on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Tenable.sc.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.168.0.1) | True |
    | Access key | False |
    | Secret key | False |
    | Username | False |
    | Password | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetch incidents | False |
    | Incident type | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tenable-sc-list-scans

***
Requires security manager authentication. Get a list of Tenable.sc existing scans

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

### tenable-sc-launch-scan

***
Requires security manager authentication. Launch an existing scan from Tenable.sc

#### Base Command

`tenable-sc-launch-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | Scan ID, can be retrieved from list-scans command. | Required | 
| diagnostic_target | Valid IP/Hostname of a specific target to scan. Must be provided with diagnosticPassword. | Optional | 
| diagnostic_password | Non empty string password. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanResults.Name | string | Scan name. | 
| TenableSC.ScanResults.ID | string | Scan Results ID. | 
| TenableSC.ScanResults.OwnerID | string | Scan owner ID. | 
| TenableSC.ScanResults.JobID | string | Job ID. | 
| TenableSC.ScanResults.Status | string | Scan status. | 

### tenable-sc-get-vulnerability

***
Requires security manager authentication. Get details about a given vulnerability from a given Tenable.sc scan

#### Base Command

`tenable-sc-get-vulnerability`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerability_id | Vulnerability ID from the scan-report command. | Required | 
| scan_results_id | Scan results ID from the scan-report command. | Optional | 
| query_id | Can be created via the Tenable.sc UI &gt; Analysis &gt; queries. can be retrieved from tenable-sc-list-query command. | Optional | 
| sort_direction | Default is 'ASC'. Requires companion parameter, sort_field. Possible values are: ASC, DESC. Default is ASC. | Optional | 
| sort_field | Which field to sort by, For vulnerabilities data, Tenable recommends you sort by severity. Default is severity. | Optional | 
| source_type | When the source_type is "individual", a scan_results_id must be provided. cumulative — Analyzes cumulative vulnerabilities. patched — Analyzes mitigated vulnerabilities. Possible values are: individual, cumulative, patched. Default is individual. | Optional | 
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

### tenable-sc-get-scan-status

***
Requires security manager authentication. Get the status of a specific scan in Tenable.sc.

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
| TenableSC.ScanResults.Description | Unknown | Scan description. | 
| TenableSC.ScanResults.ID | Unknown | Scan results ID. | 

### tenable-sc-get-scan-report

***
Requires security manager authentication. Get a single report with Tenable.sc scan results.

#### Base Command

`tenable-sc-get-scan-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_results_id | Scan results ID. | Required | 
| vulnerability_severity | Comma separated list of severity values of vulnerabilities to retrieve. Default is Critical,High,Medium,Low,Info. | Optional | 

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

### tenable-sc-list-credentials

***
Requires security manager authentication. Get a list of Tenable.sc credentials.

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

### tenable-sc-list-policies

***
Requires security manager authentication. Get a list of Tenable.sc scan policies.

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

### tenable-sc-list-report-definitions

***
Requires security manager authentication. Get a list of Tenable.sc report definitions.

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

### tenable-sc-list-repositories

***
Requires security manager authentication. Get a list of Tenable.sc scan repositories.

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

### tenable-sc-list-zones

***
Requires admin authentication. Get a list of Tenable.sc scan zones.

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

### Requires security manager authentication. tenable-sc-create-scan

***
Create a scan on Tenable.sc

#### Base Command

`Requires security manager authentication. tenable-sc-create-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Scan name. | Required | 
| policy_id | Policy ID, can be retrieved from list-policies command. | Required | 
| plugin_id | Plugin ID. | Optional | 
| description | Scan description. | Optional | 
| repository_id | Scan Repository ID, can be retrieved from list-repositories command. | Required | 
| zone_id | Scan zone ID (default is all zones), can be retrieved from list-zones command. | Optional | 
| schedule | Schedule for the scan. Possible values are: dependent, ical, never, rollover, now. | Optional | 
| asset_ids | Either all assets or comma separated asset IDs to scan, can be retrieved from list-assets command. Possible values are: All, AllManageable. | Optional | 
| scan_virtual_hosts | Whether to includes virtual hosts, default false. Possible values are: true, false. | Optional | 
| ip_list | Comma separated IPs to scan e.g 10.0.0.1,10.0.0.2 . | Optional | 
| report_ids | Comma separated list of report definition IDs to create post-scan, can be retrieved from list-report-definitions command. | Optional | 
| credentials | Comma separated credentials IDs to use, can be retrieved from list-credentials command. | Optional | 
| timeout_action | Scan timeout action, default is import. Possible values are: discard, import, rollover. | Optional | 
| max_scan_time | Maximum scan run time in hours, default is 1. | Optional | 
| dhcp_tracking | Track hosts which have been issued new IP address, (e.g. DHCP). Possible values are: true, false. | Optional | 
| rollover_type | Scan rollover type. Possible values are: nextDay. | Optional | 
| dependent_id | Dependent scan ID in case of a dependent schedule, can be retrieved from list-scans command. | Optional | 
| time_zone | The timezone for the given start_time, possible values can be found here: https://docs.oracle.com/middleware/1221/wcs/tag-ref/MISC/TimeZones.html. | Optional | 
| start_time | The scan start time, should be in the format of YYYY-MM-DD:HH:MM:SS or relative timestamp (i.e now, 3 days). | Optional | 
| repeat_rule_freq | to specify repeating events based on an interval of a repeat_rule_freq or more. Possible values are: HOURLY, DAILY, WEEKLY, MONTHLY, YEARLY. | Optional | 
| repeat_rule_interval | the number of repeat_rule_freq between each interval (for example: If repeat_rule_freq=DAILY and repeat_rule_interval=8 it means every eight days.). | Optional | 
| repeat_rule_by_day | A comma-separated list of days of the week to run the schedule at. Possible values are: SU, MO, TU, WE, TH, FR, SA. | Optional | 
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

### tenable-sc-delete-scan

***
Requires security manager authentication. Delete a scan in Tenable.sc

#### Base Command

`tenable-sc-delete-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | Scan ID, can be. retrieved from the list-scans command. | Required | 

#### Context Output

There is no context output for this command.
### tenable-sc-list-assets

***
Requires security manager authentication. Get a list of Tenable.sc Assets.

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
| TenableSC.Asset.Name | string | Asset Name. | 
| TenableSC.Asset.HostCount | number | Asset host IPs count. | 
| TenableSC.Asset.Type | string | Asset type. | 
| TenableSC.Asset.Tag | string | Asset tag. | 
| TenableSC.Asset.Owner | string | Asset owner username. | 
| TenableSC.Asset.Group | string | Asset group. | 
| TenableSC.Asset.LastModified | date | Asset last modified time. | 

### tenable-sc-create-asset

***
Requires security manager authentication. Create an Asset in Tenable.sc with provided IP addresses.

#### Base Command

`tenable-sc-create-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Asset Name. | Required | 
| description | Asset description. | Optional | 
| owner_id | Asset owner ID, default is the Session User ID, can be retrieved from the list-users command. | Optional | 
| tag | Asset tag. | Optional | 
| ip_list | Comma separated list of IPs to include in the asset, e.g 10.0.0.2,10.0.0.4. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Asset.Name | string | Asset Name. | 
| TenableSC.Asset.ID | string | Asset ID. | 
| TenableSC.Asset.OwnerName | string | Asset owner name. | 
| TenableSC.Asset.Tags | string | Asset tags. | 

### tenable-sc-get-asset

***
Requires security manager authentication. Get details for a given asset in Tenable.sc.

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

### tenable-sc-delete-asset

***
Requires security manager authentication. Delete the Asset with the given ID from Tenable.sc.

#### Base Command

`tenable-sc-delete-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required | 

#### Context Output

There is no context output for this command.
### tenable-sc-list-alerts

***
Requires security manager authentication. List alerts from Tenable.sc.

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
| TenableSC.Alert.Actions | string | Alert Actions. | 
| TenableSC.Alert.LastTriggered | date | Alert last triggered time. | 
| TenableSC.Alert.LastEvaluated | date | Alert last evaluated time. | 
| TenableSC.Alert.Group | string | Alert owner group name. | 
| TenableSC.Alert.Owner | string | Alert owner user name. | 

### tenable-sc-get-alert

***
Requires security manager authentication. Get information about a given alert in Tenable.sc.

#### Base Command

`tenable-sc-get-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID, can be retrieved from list-alerts command. | Required | 

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

### tenable-sc-get-device

***
Requires security manager authentication. Gets the specified device information.

#### Base Command

`tenable-sc-get-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A valid IP address of a device. | Optional | 
| dns_name | DNS name of a device. | Optional | 
| repository_id | Repository ID to get the device from, can be retrieved from list-repositories command. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Device.IP | string | Device IP address. | 
| TenableSC.Device.UUID | string | Device UUID. | 
| TenableSC.Device.RepositoryID | string | Device repository ID. | 
| TenableSC.Device.MacAddress | string | Device Mac address. | 
| TenableSC.Device.NetbiosName | string | Device Netbios name. | 
| TenableSC.Device.DNSName | string | Device DNS name. | 
| TenableSC.Device.OS | string | Device Operating System. | 
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
| Endpoint.MACAddress | string | Endpoint mac address. | 
| Endpoint.OS | string | Endpoint OS. | 

### tenable-sc-list-users

***
Results may vary based on the authentication type (admin or security manager). List users in Tenable.sc.

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

### tenable-sc-get-system-licensing

***
Requires admin authentication. Retrieve licensing information from Tenable.sc

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

### tenable-sc-get-system-information

***
Requires admin authentication. Get the system information and diagnostics from Tenable.sc.

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
| TenableSC.System.JavaStatus | boolean | Server java status. | 
| TenableSC.System.RPMStatus | boolean | Server RPM status. | 
| TenableSC.System.DiskStatus | boolean | Server disk status. | 
| TenableSC.System.DiskThreshold | number | System left space on disk. | 
| TenableSC.System.LastCheck | date | System last check time. | 

### tenable-sc-get-all-scan-results

***
Requires security manager authentication. Returns all scan results in Tenable.sc.

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

### tenable-sc-list-groups

***
Requires security manager authentication. list all groups.

#### Base Command

`tenable-sc-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| show_users | Wether to show group member or not. Default is True. Possible values are: true, false. Default is true. | Optional | 
| limit | The number of objects to return in one response. Default is 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Group.Name | string | Group name. | 
| TenableSC.Group.ID | number | Group ID. | 
| TenableSC.Group.Description | string | Group description. | 
| TenableSC.Group.Users.Firstname | string | Group's user's first name. | 
| TenableSC.Group.Users.Lastname | string | Group's user's last name. | 
| TenableSC.Group.Users.ID | string | Group's user's id. | 
| TenableSC.Group.Users.UUID | string | Group's user's uuid. | 
| TenableSC.Group.Users.Username | string | Group's user's user name. | 

### tenable-sc-create-user

***
This command can be executed with both authentication types (admin or security manager) based on the roll_id you with to choose. Creates a new user.

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
| locked | Default is False. Wether the user should be locked or not. Possible values are: true, false. Default is false. | Optional | 
| email_notice | If different from None, a valid email address must be given. Possible values are: both, password, id, none. Default is none. | Optional | 
| auth_type | Tenable (TNS). Lightweight Directory Access Protocol (LDAP). Security Assertion Markup Language (SAML). LDAP server or SAML authentication need to be configured in order to select LDAP or SAML. Possible values are: Ldap, legacy, linked, saml, tns. Default is tns. | Required | 
| password | The user's password. Must be at least 3 characters. | Required | 
| time_zone | The user timezone, possible values can be found here: https://docs.oracle.com/middleware/1221/wcs/tag-ref/MISC/TimeZones.html. | Optional | 
| role_id | The user's role. Should be a number between 1 to 7. Role description: 1- Administrator, 2- Security Manager, 3-Security Analyst, 4-Vulnerability Analyst, 5-Executive, 6-Credential Manager, 7-Auditor. Only an Administrator can create Administrator accounts. Possible values are: 0, 1, 2, 3, 4, 5, 6, 7. | Required | 
| must_change_password | When choosing LDAP or SAML auth types, 'must_change_password' must be set to False. For all other cases can be either True or False. Possible values are: false, true. Default is false. | Optional | 
| managed_users_groups | Comma separated list of session user's role can manage group. Use tenable-sc-list-groups to get all available groups. Default is 0. | Optional | 
| managed_objects_groups | Comma separated list of session user's role can manage group. Use tenable-sc-list-groups to get all available groups. Default is 0. | Optional | 
| group_id | Default is 0. Valid group ID whose users can be managed by created user. | Required | 
| responsible_asset_id | Default is 0. ID of a valid, usable, accessible asset. Use tenable-sc-list-assets to get all available assets. -1 is not set, 0 is all assets, and other numbers are asset id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.User.Address | String | User address. | 
| TenableSC.User.ApiKeys | Unknown | User api keys. | 
| TenableSC.User.AuthType | String | User auth type. | 
| TenableSC.User.CanManage | Boolean | User permissions. | 
| TenableSC.User.CanUse | Boolean | User permissions. | 
| TenableSC.User.City | String | User city of residence. | 
| TenableSC.User.Country | String | User country of residence. | 
| TenableSC.User.CreatedTime | Date | User creation time. | 
| TenableSC.User.Email | String | User email address. | 
| TenableSC.User.FailedLogins | String | User number of failed logins. | 
| TenableSC.User.Fax | String | User fax. | 
| TenableSC.User.Fingerprint | Unknown | User fingerprint. | 
| TenableSC.User.Firstname | String | User first name. | 
| TenableSC.User.group.Description | String | User group's description. | 
| TenableSC.User.Group.ID | String | User group's id. | 
| TenableSC.User.Group.Name | String | User group's name. | 
| TenableSC.User.ID | String | User id. | 
| TenableSC.User.LastLogin | String | User last login time. | 
| TenableSC.User.LastLoginIP | String | User last login IP. | 
| TenableSC.User.Lastname | String | User last name. | 
| TenableSC.User.Ldap.Description | String | User ldap description. | 
| TenableSC.User.Ldap.ID | Number | User ldap ID&gt; | 
| TenableSC.User.Ldap.Name | String | User ldap name. | 
| TenableSC.User.LdapUsername | String | user ldap username. | 
| TenableSC.User.Locked | String | if user is locked or not. | 
| TenableSC.User.ManagedObjectsGroups.Description | String | User managed object groups description. | 
| TenableSC.User.ManagedObjectsGroups.ID | String | User managed object groups id | 
| TenableSC.User.ManagedObjectsGroups.Name | String | User managed object groups name. | 
| TenableSC.User.ManagedUsersGroups.Description | String | User managed users groups description. | 
| TenableSC.User.ManagedUsersGroups.ID | String | User managed users groups id. | 
| TenableSC.User.ManagedUsersGroups.Name | String | User managed users groups name. | 
| TenableSC.User.ModifiedTime | Date | User last modification time. | 
| TenableSC.User.MustChangePassword | String | If user must change password. | 
| TenableSC.User.Password | String | If user password is set. | 
| TenableSC.User.Phone | String | User phone number. | 
| TenableSC.User.Preferences.Name | String | User preferences name. | 
| TenableSC.User.Preferences.Tag | String | User preferences tag. | 
| TenableSC.User.Preferences.Value | String | User preferences value. | 
| TenableSC.User.ResponsibleAsset.Description | String | User responsible asset description. | 
| TenableSC.User.ResponsibleAsset.ID | String | User responsible asset id. | 
| TenableSC.User.ResponsibleAsset.Name | String | User responsible asset name. | 
| TenableSC.User.ResponsibleAsset.UUID | Unknown | User responsible asset UUID. | 
| TenableSC.User.Role.Description | String | User tole description. | 
| TenableSC.User.Role.ID | String | User role id. | 
| TenableSC.User.Role.Name | String | User role name | 
| TenableSC.User.State | String | User state. | 
| TenableSC.User.Status | String | User status. | 
| TenableSC.User.Title | String | User title. | 
| TenableSC.User.Username | String | User username. | 
| TenableSC.User.UUID | String | User UUID. | 

### tenable-sc-update-user

***
update user details by given user_id.

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
| locked | Default is False. Wether the user should be locked or not. Possible values are: true, false. Default is false. | Optional | 
| time_zone | The user timezone, possible values can be found here: https://docs.oracle.com/middleware/1221/wcs/tag-ref/MISC/TimeZones.html. | Optional | 
| role_id | The user's role. Should be a number between 1 to 7. Role description: 1- Administrator, 2- Security Manager, 3-Security Analyst, 4-Vulnerability Analyst, 5-Executive, 6-Credential Manager, 7-Auditor. Only an Administrator can create Administrator accounts. Possible values are: 0, 1, 2, 3, 4, 5, 6, 7. | Optional | 
| must_change_password | When choosing LDAP or SAML auth types, 'must_change_password' must be set to False. For all other cases can be either True or False. Possible values are: false, true. Default is false. | Optional | 
| managed_users_groups | Comma separated list of session user's role can manage group. Use tenable-sc-list-groups to get all available groups. Default is 0. | Optional | 
| managed_objects_groups | Comma separated list of session user's role can manage group. Use tenable-sc-list-groups to get all available groups. Default is 0. | Optional | 
| group_id | Default is 0. Valid group ID whose users can be managed by created user. | Optional | 
| responsible_asset_id | Default is 0. ID of a valid, usable, accessible asset. Use tenable-sc-list-assets to get all available assets. -1 is not set, 0 is all assets, and other numbers are asset id. | Optional | 
| password | The new password to set. Must be given with current_password. Must be at least 3 characters. | Optional | 
| current_password | This is admin/Security Manager password from instance parameters. required when attempting to change user's password. | Optional | 
| user_id | The id of the user whose details we wish to update. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.User.Address | String | User address. | 
| TenableSC.User.ApiKeys | Unknown | User api keys. | 
| TenableSC.User.AuthType | String | User auth type. | 
| TenableSC.User.CanManage | Boolean | User permissions. | 
| TenableSC.User.CanUse | Boolean | User permissions. | 
| TenableSC.User.City | String | User city of residence. | 
| TenableSC.User.Country | String | User country of residence. | 
| TenableSC.User.CreatedTime | Date | User creation time. | 
| TenableSC.User.Email | String | User email address. | 
| TenableSC.User.FailedLogins | String | User number of failed logins. | 
| TenableSC.User.Fax | String | User fax. | 
| TenableSC.User.Fingerprint | Unknown | User fingerprint. | 
| TenableSC.User.Firstname | String | User first name. | 
| TenableSC.User.group.Description | String | User group's description. | 
| TenableSC.User.Group.ID | String | User group's id. | 
| TenableSC.User.Group.Name | String | User group's name. | 
| TenableSC.User.ID | String | User id. | 
| TenableSC.User.LastLogin | String | User last login time. | 
| TenableSC.User.LastLoginIP | String | User last login IP. | 
| TenableSC.User.Lastname | String | User last name. | 
| TenableSC.User.Ldap.Description | String | User ldap description. | 
| TenableSC.User.Ldap.ID | Number | User ldap ID&gt; | 
| TenableSC.User.Ldap.Name | String | User ldap name. | 
| TenableSC.User.LdapUsername | String | user ldap username. | 
| TenableSC.User.Locked | String | if user is locked or not. | 
| TenableSC.User.ManagedObjectsGroups.Description | String | User managed object groups description. | 
| TenableSC.User.ManagedObjectsGroups.ID | String | User managed object groups id | 
| TenableSC.User.ManagedObjectsGroups.Name | String | User managed object groups name. | 
| TenableSC.User.ManagedUsersGroups.Description | String | User managed users groups description. | 
| TenableSC.User.ManagedUsersGroups.ID | String | User managed users groups id. | 
| TenableSC.User.ManagedUsersGroups.Name | String | User managed users groups name. | 
| TenableSC.User.ModifiedTime | Date | User last modification time. | 
| TenableSC.User.MustChangePassword | String | If user must change password. | 
| TenableSC.User.Password | String | If user password is set. | 
| TenableSC.User.Phone | String | User phone number. | 
| TenableSC.User.Preferences.Name | String | User preferences name. | 
| TenableSC.User.Preferences.Tag | String | User preferences tag. | 
| TenableSC.User.Preferences.Value | String | User preferences value. | 
| TenableSC.User.ResponsibleAsset.Description | String | User responsible asset description. | 
| TenableSC.User.ResponsibleAsset.ID | String | User responsible asset id. | 
| TenableSC.User.ResponsibleAsset.Name | String | User responsible asset name. | 
| TenableSC.User.ResponsibleAsset.UUID | Unknown | User responsible asset UUID. | 
| TenableSC.User.Role.Description | String | User tole description. | 
| TenableSC.User.Role.ID | String | User role id. | 
| TenableSC.User.Role.Name | String | User role name | 
| TenableSC.User.State | String | User state. | 
| TenableSC.User.Status | String | User status. | 
| TenableSC.User.Title | String | User title. | 
| TenableSC.User.Username | String | User username. | 
| TenableSC.User.UUID | String | User UUID. | 

### tenable-sc-delete-user

***
This command can be executed with both authentication types (admin or security manager). Delete a user by given user_id.

#### Base Command

`tenable-sc-delete-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The id of the user we want to delete. | Required | 

#### Context Output

There is no context output for this command.
### tenable-sc-list-plugin-family

***
Requires security manager authentication. list plugin families / return information about a plugin family given ID.

#### Base Command

`tenable-sc-list-plugin-family`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| plugin_id | The id of the plugin we want to search. If given, other arguments will be ignored. | Optional | 
| limit | Default is 50. The number of objects to return in one response (maximum limit is 200). Ignored when plugin_id is given. Default is 50. | Optional | 
| is_active | default is none. none - both active and passive Plugin Families are returned. true - Only active Plugin Families will be returned. false - Only passive Plugin Families will be returned. Ignored when plugin_id is given. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.PluginFamily.ID | String | PluginFamily ID. | 
| TenableSC.PluginFamily.Name | String | PluginFamily name. | 
| TenableSC.PluginFamily.Count | String | Number of plugins in family. | 
| TenableSC.PluginFamily.Plugins | String | The plugins list. | 
| TenableSC.PluginFamily.Type | String | PluginFamily type. | 

### tenable-sc-create-policy

***
Requires security manager authentication. This command is prerequisite for creating remediation scan. creates policy.

#### Base Command

`tenable-sc-create-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the policy you wish to create. | Optional | 
| policy_description | The description of the policy you wish to create. | Optional | 
| policy_template_id | Default is 1. Policy template id. Default is 1. | Required | 
| port_scan_range | Possible values: default, all or a comma separated list of values - 21,23,25,80,110. | Optional | 
| tcp_scanner | Only possible if you are using Linux or FreeBSD. On Windows or macOS, the scanner does not do a TCP scan and instead uses the SYN scanner..If you enable this option, you can also set the syn_firewall_detection. Possible values are: no, yes. Default is no. | Optional | 
| syn_scanner | Identifies open TCP ports on the target hosts. If you enable this option, you can also set the syn_firewall_detection option. Possible values are: no, yes. Default is yes. | Optional | 
| udp_scanner | Enabling the UDP port scanner may dramatically increase the scan time and produce unreliable results. Consider using the netstat or SNMP port enumeration options instead if possible. Possible values are: no, yes. Default is no. | Optional | 
| family_id | Can be retrieved from the result of  tenable-sc-list-plugin-family command . | Required | 
| plugins_id | Comma separated list of plugin_ids, Can be retrieved from the result of  tenable-sc-list-plugin-family command  with family_id as argument. | Required | 
| syn_firewall_detection | Default is Automatic (normal). Rely on local port enumeration first before relying on network port scans. Possible values are: Automatic (normal), Do not detect RST rate limitation(soft), Ignore closed ports(aggressive), Disabled(softer). Default is Automatic (normal). | Optional | 

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
| TenableSC.ScanPolicy.Owner.Username | String | Policy owner user name. | 
| TenableSC.ScanPolicy.Owner.UUID | String | Policy owner UUID. | 
| TenableSC.ScanPolicy.OwnerGroup.Description | String | Policy owner group description. | 
| TenableSC.ScanPolicy.OwnerGroup.ID | String | Policy owner group ID. | 
| TenableSC.ScanPolicy.OwnerGroup.Name | String | Policy owner group name. | 
| TenableSC.ScanPolicy.PolicyTemplate.Agent | String | Policy template agent. | 
| TenableSC.ScanPolicy.PolicyTemplate.Description | String | Policy template description. | 
| TenableSC.ScanPolicy.PolicyTemplate.ID | String | Policy template ID. | 
| TenableSC.ScanPolicy.PolicyTemplate.Name | String | Policy template name. | 
| TenableSC.ScanPolicy.Preferences.PortscanRange | String | Policy port scan range. | 
| TenableSC.ScanPolicy.Preferences.SynFirewallDetection | String | Policy SYN Firewall detection. | 
| TenableSC.ScanPolicy.Preferences.SynScanner | String | Policy SYN scanner. | 
| TenableSC.ScanPolicy.Preferences.TcpScanner | String | Policy TCP scanner. | 
| TenableSC.ScanPolicy.Preferences.UdpScanner | String | Policy UDP scanner. | 
| TenableSC.ScanPolicy.Status | String | Policy status. | 
| TenableSC.ScanPolicy.tags | String | Policy tags. | 
| TenableSC.ScanPolicy.TargetGroup.Description | String | Policy target group description. | 
| TenableSC.ScanPolicy.TargetGroup.ID | Number | Policy target group ID. | 
| TenableSC.ScanPolicy.TargetGroup.Name | String | Policy target group name. | 
| TenableSC.ScanPolicy.UUID | String | Policy UUID. | 

### tenable-sc-list-query

***
Requires security manager authentication. Lists queries.

#### Base Command

`tenable-sc-list-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The id of the query we wish to search. | Optional | 
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
| TenableSC.Query.Manageable.Name | String | Relevant only when query_id is not given. Manageable Query name | 
| TenableSC.Query.Manageable.Owner.Firstname | String | Relevant only when query_id is not given. Manageable Query owner first name. | 
| TenableSC.Query.Manageable.Owner.ID | String | Relevant only when query_id is not given. Manageable Query owner ID. | 
| TenableSC.Query.Manageable.Owner.Lastname | String | Relevant only when query_id is not given. Manageable Query owner last name. | 
| TenableSC.Query.Manageable.Owner.Username | String | Relevant only when query_id is not given. Manageable Query owner user name. | 
| TenableSC.Query.Manageable.Owner.UUID | String | Relevant only when query_id is not given. Manageable Query owner UUID. | 
| TenableSC.Query.Manageable.OwnerGroup.Description | String | Relevant only when query_id is not given. Manageable Query owner group description. | 
| TenableSC.Query.Manageable.OwnerGroup.ID | String | Relevant only when query_id is not given. Manageable Query owner group ID. | 
| TenableSC.Query.Manageable.OwnerGroup.Name | String | Relevant only when query_id is not given. Manageable Query owner group name. | 
| TenableSC.Query.Manageable.Status | String | Relevant only when query_id is not given. Manageable Query status | 
| TenableSC.Query.Manageable.Tags | String | Relevant only when query_id is not given. Manageable Query tags | 
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
| TenableSC.Query.Usable.Filters.Value | String | Relevant only when query_id is not given. Usable Query filter value | 
| TenableSC.Query.Usable.Groups | Unknown | Relevant only when query_id is not given. Usable Query groups. | 
| TenableSC.Query.Usable.ID | String | Relevant only when query_id is not given. Usable Query ID. | 
| TenableSC.Query.Usable.ModifiedTime | Date | Relevant only when query_id is not given. Usable Query modification time. | 
| TenableSC.Query.Usable.Name | String | Relevant only when query_id is not given. Usable Query name | 
| TenableSC.Query.Usable.Owner.Firstname | String | Relevant only when query_id is not given. Usable Query owner first name. | 
| TenableSC.Query.Usable.Owner.ID | String | Relevant only when query_id is not given. Usable Query owner ID. | 
| TenableSC.Query.Usable.Owner.Lastname | String | Relevant only when query_id is not given. Usable Query owner last name. | 
| TenableSC.Query.Usable.Owner.Username | String | Relevant only when query_id is not given. Usable Query owner user name. | 
| TenableSC.Query.Usable.Owner.UUID | String | Relevant only when query_id is not given. Usable Query owner UUID. | 
| TenableSC.Query.Usable.OwnerGroup.Description | String | Relevant only when query_id is not given. Usable Query owner group description. | 
| TenableSC.Query.Usable.OwnerGroup.ID | String | Relevant only when query_id is not given. Usable Query owner group ID. | 
| TenableSC.Query.Usable.OwnerGroup.Name | String | Relevant only when query_id is not given. Usable Query owner group name. | 
| TenableSC.Query.Usable.Status | String | Relevant only when query_id is not given. Usable Query status | 
| TenableSC.Query.Usable.Tags | String | Relevant only when query_id is not given. Usable Query tags | 
| TenableSC.Query.Usable.TargetGroup.Description | String | Relevant only when query_id is not given. Usable Query target group description. | 
| TenableSC.Query.Usable.TargetGroup.ID | Number | Relevant only when query_id is not given. Usable Query target group ID. | 
| TenableSC.Query.Usable.TargetGroup.Name | String | Relevant only when query_id is not given. Usable Query target group name. | 
| TenableSC.Query.Usable.Tool | String | Relevant only when query_id is not given. Usable Query tool. | 
| TenableSC.Query.Usable.Type | String | Relevant only when query_id is not given. Usable Query type. | 
| TenableSC.Query.Usable.Filters.Value.Description | String | Relevant only when query_id is not given. Usable Query filter value description. | 
| TenableSC.Query.Usable.Filters.Value.ID | String | Relevant only when query_id is not given. Usable Query filter value ID. | 
| TenableSC.Query.Usable.Filters.Value.Name | String | Relevant only when query_id is not given. Usable Query filter value name. | 
| TenableSC.Query.Usable.Filters.Value.Type | String | Relevant only when query_id is not given. Usable Query filter value type. | 
| TenableSC.Query.Usable.Filters.Value.UUID | String | Relevant only when query_id is not given. Usable Query filter value UUID | 
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

### tenable-sc-update-asset

***
Requires security manager authentication. Update an asset.

#### Base Command

`tenable-sc-update-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Asset name. | Optional | 
| asset_id | The ID of the asset we wish to update. | Required | 
| description | The asset description. | Optional | 
| owner_id | The asset owner ID. | Optional | 
| tag | The asset tag. | Optional | 
| ip_list | Comma separated list of the asset IPs list. | Optional | 

#### Context Output

There is no context output for this command.
### tenable-sc-create-remediation-scan

***
Requires security manager authentication. This command is prerequisite for creating remediation scan. creates policy.

#### Base Command

`tenable-sc-create-remediation-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the policy you wish to create. | Optional | 
| policy_description | The description of the policy you wish to create. | Optional | 
| port_scan_range | Possible values: default, all or a comma separated list of values - 21,23,25,80,110. | Optional | 
| tcp_scanner | Only possible if you are using Linux or FreeBSD. On Windows or macOS, the scanner does not do a TCP scan and instead uses the SYN scanner..If you enable this option, you can also set the syn_firewall_detection. Possible values are: no, yes. Default is no. | Optional | 
| syn_scanner | Identifies open TCP ports on the target hosts. If you enable this option, you can also set the syn_firewall_detection option. Possible values are: no, yes. Default is yes. | Optional | 
| udp_scanner | Enabling the UDP port scanner may dramatically increase the scan time and produce unreliable results. Consider using the netstat or SNMP port enumeration options instead if possible. Possible values are: no, yes. Default is no. | Optional | 
| syn_firewall_detection | Default is Automatic (normal). Rely on local port enumeration first before relying on network port scans. Possible values are: Automatic (normal), Do not detect RST rate limitation(soft), Ignore closed ports(aggressive), Disabled(softer). Default is Automatic (normal). | Optional | 
| family_id | Can be retrieved from the result of  tenable-sc-list-plugin-family command . | Required | 
| plugins_id | Comma separated list of plugin_ids, Can be retrieved from the result of  tenable-sc-list-plugin-family command  with family_id as argument. | Required | 
| scan_name | Scan name. | Required | 
| description | Scan description. | Optional | 
| repository_id | Default is 1. Scan Repository ID, can be retrieved from list-repositories command. Default is 1. | Required | 
| time_zone | The timezone for the given start_time, possible values can be found here: https://docs.oracle.com/middleware/1221/wcs/tag-ref/MISC/TimeZones.html. | Optional | 
| start_time | The scan start time, should be in the format of YYYY-MM-DD:HH:MM:SS or relative timestamp (i.e now, 3 days). | Optional | 
| repeat_rule_freq | to specify repeating events based on an interval of a repeat_rule_freq or more. Possible values are: HOURLY, DAILY, WEEKLY, MONTHLY, YEARLY. | Optional | 
| repeat_rule_interval | the number of repeat_rule_freq between each interval (for example: If repeat_rule_freq=DAILY and repeat_rule_interval=8 it means every eight days.). | Optional | 
| repeat_rule_by_day | A comma-separated list of days of the week to run the schedule at. Possible values are: SU, MO, TU, WE, TH, FR, SA. | Optional | 
| asset_ids | Either no assets or comma separated asset IDs to scan, can be retrieved from list-assets command. | Optional | 
| scan_virtual_hosts | Default is false. Whether to includes virtual hosts, default false. Possible values are: true, false. | Optional | 
| ip_list | Comma separated IPs to scan e.g 10.0.0.1,10.0.0.2 . | Optional | 
| report_ids | Comma separated list of report definition IDs to create post-scan, can be retrieved from list-report-definitions command. | Optional | 
| credentials | Comma separated credentials IDs to use, can be retrieved from list-credentials command. | Optional | 
| timeout_action | Default is import. Default. discard - do not import any of the results obtained by the scan to the database. import - Import the results of the current scan and discard the information for any unscanned targets. rollover-Import the results from the scan into the database and create a rollover scan that may be launched at a later time to complete the scan. Possible values are: discard, import, rollover. Default is import. | Optional | 
| max_scan_time | Maximum scan run time in hours, default is 1. | Optional | 
| dhcp_tracking | Default is false. Track hosts which have been issued new IP address, (e.g. DHCP). Possible values are: true, false. | Optional | 
| enabled | The "enabled" field can only be set to "false" for schedules of type "ical". For all other schedules types, "enabled" is set to "true". Possible values are: true, false. Default is true. | Optional | 
| rollover_type | Default is nextDay. Create a rollover scan scheduled to launch the next day at the same start time as the just completed scan. template-Create a rollover scan as a template for users to launch manually This field is required if the timeout_action is set to rollover. Default is nextDay. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.Scan.Assets | Unknown | Scan assets. | 
| TenableSC.Scan.CanManage | String | Scan permissions. | 
| TenableSC.Scan.CanUse | String | Scan permissions. | 
| TenableSC.Scan.ClassifyMitigatedAge | String | Scan  classify mitigated age. | 
| TenableSC.Scan.CreatedTime | Date | Scan creation time. | 
| TenableSC.Scan.Creator.Firstname | String | Scan creator first name. | 
| TenableSC.Scan.Creator.ID | String | Scan creator ID. | 
| TenableSC.Scan.Creator.Lastname | String | Scan creator last name. | 
| TenableSC.Scan.Creator.Username | String | Scan creator user name. | 
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
| TenableSC.Scan.Owner.Username | String | Scan owner user name. | 
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
| TenableSC.Scan.Policy.Owner.Username | String | Scan policy owner user name. | 
| TenableSC.Scan.Policy.Owner.UUID | String | Scan policy owner UUID. | 
| TenableSC.Scan.Policy.OwnerGroup.Description | String | Scan policy owner group description. | 
| TenableSC.Scan.Policy.OwnerGroup.ID | String | Scan policy owner group ID. | 
| TenableSC.Scan.Policy.OwnerGroup.Name | String | Scan policy owner group name. | 
| TenableSC.Scan.Policy.Tags | String | Scan policy tags | 
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
| TenableSC.Scan.ScanningVirtualHosts | String | Scan virtual hosts | 
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

### tenable-sc-launch-scan-report

***
Requires security manager authentication. Polling command. Launch a scan by given scan ID, follow its status return a report when the scan is over.

#### Base Command

`tenable-sc-launch-scan-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | The id of the scan we wish to get the report on. Can be retrieved from list-scans command. | Required | 
| diagnostic_target | Valid IP/Hostname of a specific target to scan. Must be provided with diagnostic_password. | Optional | 
| diagnostic_password | Valid password of the diagnostic_target. Must be provided with diagnostic_target. | Optional | 
| scan_results_id | Deprecated. Scan results id. | Optional | 
| timeout_in_seconds | Default is 3 hours. The timeout in seconds until polling ends. Default is 10800. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableSC.ScanResults.ID | number | Scan results ID | 
| TenableSC.ScanResults.Name | string | Scan name | 
| TenableSC.ScanResults.Status | string | Scan status | 
| TenableSC.ScanResults.ScannedIPs | number | Scan number of scanned IPs | 
| TenableSC.ScanResults.StartTime | date | Scan start time | 
| TenableSC.ScanResults.EndTime | date | Scan end time | 
| TenableSC.ScanResults.Checks | number | Scan completed checks | 
| TenableSC.ScanResults.RepositoryName | string | Scan repository name | 
| TenableSC.ScanResults.Description | string | Scan description | 
| TenableSC.ScanResults.Vulnerability.ID | number | Scan vulnerability ID | 
| TenableSC.ScanResults.Vulnerability.Name | string | Scan vulnerability Name | 
| TenableSC.ScanResults.Vulnerability.Family | string | Scan vulnerability family | 
| TenableSC.ScanResults.Vulnerability.Severity | string | Scan vulnerability severity | 
| TenableSC.ScanResults.Vulnerability.Total | number | Scan vulnerability total hosts | 
| TenableSC.ScanResults.Policy | string | Scan policy | 
| TenableSC.ScanResults.Group | string | Scan owner group name | 
| TenableSC.ScanResults.Owner | string | Scan owner user name | 
| TenableSC.ScanResults.Duration | number | Scan duration in minutes | 
| TenableSC.ScanResults.ImportTime | date | Scan import time | 
