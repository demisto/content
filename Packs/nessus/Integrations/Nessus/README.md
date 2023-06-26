
### nessus-list-scans

***
Returns the scan list

#### Base Command

`nessus-list-scans`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| foldersHeaders | The table's headers to be shown by order. | Optional | 
| scansHeaders | The table's headers to be shown by order. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NessusScan.UUID | unknown | The uuid for the scan. | 
| NessusScan.Name | unknown | The name of the scan. | 
| NessusScan.Status | unknown | The status of the scan. | 
| NessusScan.FolderID | unknown | The unique id of the folder housing the scan. | 
| NessusScan.ID | unknown | The unique id of the scan. | 
| NessusScan.UserPermissions | unknown | The sharing permissions for the scan. | 
| NessusScan.CreationDate | unknown | The creation date for the scan in unixtime. | 
| NessusScan.LastModificationDate | unknown | The last modification date for the scan in unixtime. | 
| NessusScan.Type | unknown | The type of scan \(local, remote, or agent\). | 
| NessusScan.Policy | unknown | The policy if the scan. | 
| NessusFolder.UnreadCount | unknown | The number of unread scans in the folder. | 
| NessusFolder.Custom | unknown | The custom status of the folder \(1 or 0\). | 
| NessusFolder.DefaultTag | unknown | Whether or not the folder is the default \(1 or 0\). | 
| NessusFolder.Type | unknown | The type of the folder \(main, trash, custom\). | 
| NessusFolder.Name | unknown | The name of the folder. | 
| NessusFolder.ID | unknown | The unique id of the folder. | 
### nessus-launch-scan

***
Launches a new vulnerability scan

#### Base Command

`nessus-launch-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The Scan ID (use command list-scans to get possible scan ID's). | Required | 
| targets | If specified, these targets will be scanned instead of the default. Value can be single host or of comma separated targets. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ScanUUID | unknown | The uuid of the launched scan. | 
### nessus-scan-details

***
Returns details for the given scan

#### Base Command

`nessus-scan-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The Scan ID (use command list-scans to get possible scan ID's). | Required | 
| historyId | The history_id of the historical data that should be returned. | Optional | 
| tables | The tables to be shown by order. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NessusScan.UUID | unknown | The uuid for the scan. | 
| NessusScan.Name | unknown | The name of the scan. | 
| NessusScan.Status | unknown | The status of the scan. | 
| NessusScan.FolderID | unknown | The unique id of the folder housing the scan. | 
| NessusScan.ID | unknown | The unique id of the scan. | 
| NessusScan.UserPermissions | unknown | The sharing permissions for the scan. | 
| NessusScan.CreationDate | unknown | The creation date for the scan in unixtime. | 
| NessusScan.LastModificationDate | unknown | The last modification date for the scan in unixtime. | 
| NessusScan.Type | unknown | The type of scan \(local, remote, or agent\). | 
| NessusScan.Policy | unknown | The policy if the scan. | 
| NessusScan.Endpoint.ID | unknown | The unique id of the host. | 
| NessusScan.Endpoint.Index | unknown | The index for the host. | 
| NessusScan.Endpoint.Hostname | unknown | The overall severity rating of the host. | 
| NessusScan.Endpoint.Progress | unknown | The scan progress of the host. | 
| NessusScan.Endpoint.Critical | unknown | The percentage of critical findings on the host. | 
| NessusScan.Endpoint.High | unknown | The percentage of high findings on the host. | 
| NessusScan.Endpoint.Medium | unknown | The percentage of medium findings on the host. | 
| NessusScan.Endpoint.Low | unknown | The percentage of low findings on the host. | 
| NessusScan.Endpoint.Info | unknown | The percentage of info findings on the host. | 
| NessusScan.Endpoint.TotalChecksConsidered | unknown | The total number of checks considered on the host. | 
| NessusScan.Endpoint.NumChecksConsidered | unknown | The number of checks considered on the host. | 
| NessusScan.Endpoint.ScanProgressTotal | unknown | The total scan progress for the host. | 
| NessusScan.Endpoint.ScanProgressCurrent | unknown | The current scan progress for the host. | 
| NessusScan.Endpoint.Score | unknown | The overall score for the host. | 
| NessusScan.Vulnerability.PluginID | unknown | The unique id of the vulnerability plugin. | 
| NessusScan.Vulnerability.PluginName | unknown | The name of the vulnerability plugin. | 
| NessusScan.Vulnerability.PluginFamily | unknown | The parent family of the vulnerability plugin. | 
| NessusScan.Vulnerability.Count | unknown | The number of vulnerabilities found. | 
| NessusScan.Vulnerability.VulnerabilityIndex | unknown | The index of the vulnerability plugin. | 
| NessusScan.Vulnerability.SeverityIndex | unknown | The severity index order of the plugin. | 
| NessusScan.Note.Title | unknown | The title of the note. | 
| NessusScan.Note.Message | unknown | The specific message of the note. | 
| NessusScan.Note.Sevirity | unknown | The severity of the note. | 
| NessusScan.Filter.Name | unknown | The short name of the filter. | 
| NessusScan.Filter.ReadableName | unknown | The long name of the filter. | 
| NessusScan.Filter.Operators | unknown | The comparison options for the filter. | 
| NessusScan.Filter.Type | unknown | The input type for the filter. | 
| NessusScan.Filter.ReadableRegest | unknown | The input placeholder for the filter. | 
| NessusScan.Filter.Regex | unknown | The input regex values for the filter. | 
| NessusScan.Filter.Options | unknown | Other input options for the filter. | 
| NessusScan.History.ID | unknown | The unique id of the historical data. | 
| NessusScan.History.UUID | unknown | The uuid of the historical data. | 
| NessusScan.History.OwnerID | unknown | The unique id of the owner of the scan. | 
| NessusScan.History.Status | unknown | The status of the historical data. | 
| NessusScan.History.CreationDate | unknown | The creation date for the historical data in unixtime. | 
| NessusScan.History.LastModification_date | unknown | The last modification date for the historical data in unixtime. | 
| NessusScan.Remediations.Remediations | unknown | Remedy to vulnerabilites found during the scan. | 
| NessusScan.Remediations.NumHosts | unknown | Number of hosts of Remediations | 
| NessusScan.Remediations.NumCVEs | unknown | Number of CVE's | 
| NessusScan.Remediations.NumImpactedHosts | unknown | Number of impacted hosts | 
| NessusScan.Remediations.NumRemediatedCVEs | unknown | Number of Remediated CVE's | 
### nessus-scan-host-details

***
Returns details for the given host.

#### Base Command

`nessus-scan-host-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The Scan ID (use command list-scans to get possible scan ID's). | Required | 
| historyId | The history_id of the historical data that should be returned. | Optional | 
| hostId | The id of the host to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.ID | unknown | The unique id of the host. | 
| Endpoint.Index | unknown | The index for the host. | 
| Endpoint.Hostname | unknown | The overall severity rating of the host. | 
| Endpoint.Progress | unknown | The scan progress of the host. | 
| Endpoint.Critical | unknown | The percentage of critical findings on the host. | 
| Endpoint.High | unknown | The percentage of high findings on the host. | 
| Endpoint.Medium | unknown | The percentage of medium findings on the host. | 
| Endpoint.Low | unknown | The percentage of low findings on the host. | 
| Endpoint.Info | unknown | The percentage of info findings on the host. | 
| Endpoint.TotalChecksConsidered | unknown | The total number of checks considered on the host. | 
| Endpoint.NumChecksConsidered | unknown | The number of checks considered on the host. | 
| Endpoint.ScanProgressTotal | unknown | The total scan progress for the host. | 
| Endpoint.ScanProgressCurrent | unknown | The current scan progress for the host. | 
| Endpoint.Score | unknown | The overall score for the host. | 
### nessus-scan-export

***
Export the given scan (Nessus, HTML, PDF, CSV, or DB format)

#### Base Command

`nessus-scan-export`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The Scan ID (use command list-scans to get possible scan ID's). | Required | 
| historyId | The history_id of the historical data that should be returned. | Optional | 
| format | scan report file format (nessus, csv, html, db, pdf). | Required | 
| password | The password used to encrypt database exports (*Required when exporting as DB). | Optional | 
| chapters | The chapters to include in the export (expecting a semi-colon delimited string comprised of some combination of the following options: vuln_hosts_summary, vuln_by_host, compliance_exec, remediations, vuln_by_plugin, compliance). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ScanReportID | unknown | ID of the scan report. | 
### nessus-scan-report-download

***
Download an exported scan

#### Base Command

`nessus-scan-report-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The Scan ID (use command list-scans to get possible scan ID's). | Required | 
| fileId | The id of the file to download (result from command export-scan). | Required | 

#### Context Output

There is no context output for this command.
### nessus-scan-create

***
Creates a new scan

#### Base Command

`nessus-scan-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| editor | The uuid for the editor template to use. | Required | 
| name | The name of the scan. | Required | 
| description | The description of the scan. | Optional | 
| policyId | The unique id of the policy to use(number). | Optional | 
| folderId | The unique id of the destination folder for the scan(number). | Optional | 
| scannerId | The unique id of the scanner to use(number). | Optional | 
| schedule | If true, the schedule for the scan is enabled(true/false). | Required | 
| launch | When to launch the scan. (i.e. ON_DEMAND, DAILY, WEEKLY, MONTHLY, YEARLY). | Optional | 
| startTime | The starting time and date for the scan (i.e. YYYYMMDDTHHMMSS). | Optional | 
| rules | Expects a semi-colon delimited string comprised of three values. The frequency (FREQ=ONCE or DAILY or WEEKLY or MONTHLY or YEARLY), the interval (INTERVAL=1 or 2 or 3 ... x), and the days of the week (BYDAY=SU,MO,TU,WE,TH,FR,SA). To create a scan that runs every three weeks on Monday Wednesday and Friday the string would be 'FREQ=WEEKLY;INTERVAL=3;BYDAY=MO,WE,FR'. | Optional | 
| timeZone | The timezone for the scan schedule. | Optional | 
| targets | The list of targets to scan, Value can be single host or of comma separated targets. | Required | 
| emails | A comma separated list of accounts who will recieve the email summary report. | Optional | 
| acls | An array containing permissions to apply to the scan. | Optional | 
| fileTargets | The name of a file containing the list of targets to scan. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NessusScan.UUID | unknown | The uuid for the scan. | 
| NessusScan.Name | unknown | The name of the scan. | 
| NessusScan.Status | unknown | The status of the scan. | 
| NessusScan.FolderID | unknown | The unique id of the folder housing the scan. | 
| NessusScan.ID | unknown | The unique id of the scan. | 
| NessusScan.UserPermissions | unknown | The sharing permissions for the scan. | 
| NessusScan.CreationDate | unknown | The creation date for the scan in unixtime. | 
| NessusScan.LastModificationDate | unknown | The last modification date for the scan in unixtime. | 
| NessusScan.Type | unknown | The type of scan \(local, remote, or agent\). | 
| NessusScan.Policy | unknown | The policy if the scan. | 
### nessus-get-scans-editors

***
Returns all scan editors template list

#### Base Command

`nessus-get-scans-editors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### nessus-scan-export-status

***
Check the file status of an exported scan

#### Base Command

`nessus-scan-export-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The Scan ID (use command list-scans to get possible scan ID's). | Required | 
| fileId | The id of the file to download (result from command export-scan). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NessusScan.ScanReportStatus | unknown | The status of the scan report. | 
### nessus-scan-status

***
Get scan status by scan id

#### Base Command

`nessus-scan-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The Scan ID (use command list-scans to get possible scan ID's). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NessusScan.Status | unknown | The status of the scan report. | 
