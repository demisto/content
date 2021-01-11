A comprehensive asset centric solution to accurately track resources while accommodating dynamic assets such as cloud, mobile devices, containers and web applications.
This integration was integrated and tested with version xx of Tenable.io_Custom
## Configure Tenable.io_Custom on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Tenable.io_Custom.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | URL | True |
| access-key | Access Key | True |
| secret-key | Secret Key | True |
| unsecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### tenable-io-list-scans
***
Retrive scans from the Tenable platform.


#### Base Command

`tenable-io-list-scans`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folderId | The ID of the folder whose scans should be listed. Scans are stored<br/>in specific folders on Tenable. e.g : folderId=8 | Optional | 
| lastModificationDate | Limit the results to those that have only changed since this time. Format: YYYY-MM-DD | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | number | The unique id of the scan. | 
| TenableIO.Scan.Name | string | The name of the scan. | 
| TenableIO.Scan.Target | string | The targets to be scanned. | 
| TenableIO.Scan.Status | string | The status of the scan \(completed, aborted, imported, pending, running, resuming, canceling, cancelled, pausing, paused, stopping, stopped\). | 
| TenableIO.Scan.StartTime | date | The scheduled start time for the scan. | 
| TenableIO.Scan.EndTime | date | The scan end time for the scan. | 
| TenableIO.Scan.Enabled | boolean | If true, the schedule for the scan is enabled. | 
| TenableIO.Scan.Type | string | The type of scan \(local, remote, or agent\). | 
| TenableIO.Scan.Owner | string | The owner of the scan. | 
| TenableIO.Scan.Scanner | string | The scanner assigned for the scan. | 
| TenableIO.Scan.Policy | string | The policy assigned for the scan. | 
| TenableIO.Scan.CreationDate | date | The creation date for the scan in Unix time. | 
| TenableIO.Scan.LastModificationDate | date | The last modification date for the scan in Unix time. | 
| TenableIO.Scan.FolderId | number | The unique id of the folder where the scan has been stored. | 


#### Command Example
``` ```

#### Human Readable Output



### tenable-io-launch-scan
***
Lauch a scan with existing or custom targets. (You can specify custom targets in the arguements of this command.)


#### Base Command

`tenable-io-launch-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The id of the scan to launch. | Required | 
| scanTargets | If specified, these targets will be scanned instead of the default. Value can be an array where each index is a target, or an array with a single index of comma separated targets. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | number | The unique id of the scan. | 
| TenableIO.Scan.Targets | string | The targets to be scanned. | 
| TenableIO.Scan.Status | string | The status of the scan \(completed, aborted, imported, pending, running, resuming, canceling, cancelled, pausing, paused, stopping, stopped\). | 


#### Command Example
``` ```

#### Human Readable Output



### tenable-io-get-scan-report
***
Retrive scan-report for the given scan.


#### Base Command

`tenable-io-get-scan-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The id of the scan to retrieve. | Required | 
| detailed | If detailed is true, the report will contain remediations and hosts information as well for the given scan. Otherwise the report will only have vulnerabilities. | Optional | 
| info | Return the basic details of the given scan. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | number | The unique id of the scan. | 
| TenableIO.Scan.Name | string | The name of the scan. | 
| TenableIO.Scan.Targets | string | The targets to be scanned. | 
| TenableIO.Scan.Status | string | The status of the scan \(completed, aborted, imported, pending, running, resuming, canceling, cancelled, pausing, paused, stopping, stopped\). | 
| TenableIO.Scan.StartTime | string | The scheduled start time for the scan. | 
| TenableIO.Scan.EndTime | string | The scan end time for the scan. | 
| TenableIO.Scan.Scanner | string | The scanner assigned for the scan. | 
| TenableIO.Scan.Policy | string | The policy assigned for the scan. | 
| TenableIO.Vulnerabilities.Id | string | The unique ID of the vulnerability. | 
| TenableIO.Vulnerabilities.Name | string | The name of the vulnerability. | 
| TenableIO.Vulnerabilities.Severity | number | The severity level of the vulnerability. | 
| TenableIO.Vulnerabilities.Description | string | The description of the vulnerability. | 
| TenableIO.Vulnerabilities.Synopsis | string | A brief summary of the vulnerability. | 
| TenableIO.Vulnerabilities.Solution | string | Information on how to fix the vulnerability. | 
| TenableIO.Vulnerabilities.FirstSeen | date | When the vulnerability was first seen. | 
| TenableIO.Vulnerabilities.LastSeen | date | When the vulnerability was last seen. | 
| TenableIO.Vulnerabilities.VulnerabilityOccurences | number | A count of the vulnerability occurrences. | 
| TenableIO.Assets.Hostname | string | The name of the host. | 
| TenableIO.Assets.Score | number | The overall score for the host. | 
| TenableIO.Assets.Critical | number | The percentage of critical findings on the host. | 
| TenableIO.Assets.High | number | The number of high findings on the host. | 
| TenableIO.Assets.Medium | number | The number of medium findings on the host. | 
| TenableIO.Assets.Low | number | The number of low findings on the host. | 
| TenableIO.Remediations.Id | string | The unique id of the remediation. | 
| TenableIO.Remediations.Description | string | Specific information related to the vulnerability and steps to remedy. | 
| TenableIO.Remediations.AffectedHosts | number | The number of hosts affected. | 
| TenableIO.Remediations.AssociatedVulnerabilities | number | The number of vulnerabilities associated with the remedy. | 
| TenableIO.Assets.Severity | unknown | Overall Severity For the host | 


#### Command Example
``` ```

#### Human Readable Output



### tenable-io-get-vulnerability-details
***
Retrieve details for the given vulnerability.


#### Base Command

`tenable-io-get-vulnerability-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vulnerabilityId | The unique ID of the vulnerability. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Vulnerabilities.Name | string | The name of the vulnerability. | 
| TenableIO.Vulnerabilities.Severity | number | Integer \[0-4\] indicating how severe the vulnerability is, where 0 is info only. | 
| TenableIO.Vulnerabilities.Type | string | The type of the vulnerability. | 
| TenableIO.Vulnerabilities.Family | string | Object containing plugin information such as family, type, and publication and modification dates. | 
| TenableIO.Vulnerabilities.Description | string | The description of the vulnerability. | 
| TenableIO.Vulnerabilities.Synopsis | string | A brief summary of the vulnerability. | 
| TenableIO.Vulnerabilities.Solution | string | Information on how to fix the vulnerability. | 
| TenableIO.Vulnerabilities.FirstSeen | date | When the vulnerability was first seen. | 
| TenableIO.Vulnerabilities.LastSeen | date | When the vulnerability was last seen. | 
| TenableIO.Vulnerabilities.PublicationDate | date | The publication date of the vulnerability. | 
| TenableIO.Vulnerabilities.ModificationDate | date | The last modification date for the vulnerability in Unix time. | 
| TenableIO.Vulnerabilities.VulnerabilityOccurences | number | A count of the vulnerability occurrences. | 
| TenableIO.Vulnerabilities.CvssVector | string | The Common Vulnerability Scoring System vector. | 
| TenableIO.Vulnerabilities.CvssBaseScore | string | The Common Vulnerability Scoring System allotted base score. | 
| TenableIO.Vulnerabilities.Cvss3Vector | string | The Common Vulnerability Scoring System version 3 vector. | 
| TenableIO.Vulnerabilities.Cvss3BaseScore | string | The Common Vulnerability Scoring System version 3 allotted base score. | 


#### Command Example
``` ```

#### Human Readable Output



### tenable-io-get-vulnerabilities-by-asset
***
Get a list of up to 5000 of the vulnerabilities recorded for a given asset.


#### Base Command

`tenable-io-get-vulnerabilities-by-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hostname of the asset. | Optional | 
| ip | IP of the asset. | Optional | 
| dateRange | The number of days of data prior to and including today that should be returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Assets.Hostname | number | Hostname of the asset. | 
| TenableIO.Assets.Vulnerabilities | number | A list of all the vuulnerability IDs associated with the asset. | 
| TenableIO.Vulnerabilities.Id | number | The unique vulnerability's ID. | 
| TenableIO.Vulnerabilities.Name | string | The name of the vulnerability's. | 
| TenableIO.Vulnerabilities.Severity | number | Integer \[0-4\] indicating how severe the vulnerability is, where 0 is info only. | 
| TenableIO.Vulnerabilities.Family | string | The vulnerability's family. | 
| TenableIO.Vulnerabilities.VulnerabilityOccurences | number | The number of times the vulnerability was found. | 
| TenableIO.Vulnerabilities.VulnerabilityState | string | The current state of the reported vulnerability \(Active, Fixed, New, etc.\) | 


#### Command Example
``` ```

#### Human Readable Output



### tenable-io-get-scan-status
***
Check the status of a specific scan using its ID. The status can
hold following possible values : Running, Completed and Empty (Ready to run).


#### Base Command

`tenable-io-get-scan-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The unique ID of the Scan. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | string | The unique ID of the scan specified. | 
| TenableIO.Scan.Status | string | The status of the scan specified. | 


#### Command Example
``` ```

#### Human Readable Output



### tenable-io-pause-scan
***
Pauses a running scan given the scan ID


#### Base Command

`tenable-io-pause-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The ID of the scan | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | unknown | The unique id of the scan. | 
| TenableIO.Scan.Status | unknown | The status of the scan \(completed, aborted, imported, pending, running, resuming, canceling, cancelled, pausing, paused, stopping, stopped\). | 


#### Command Example
``` ```

#### Human Readable Output



### tenable-io-resume-scan
***
Resumes a paused scan given the scan ID


#### Base Command

`tenable-io-resume-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | Scan ID to be resumed | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | unknown | The unique id of the scan. | 
| TenableIO.Scan.Status | unknown | The status of the scan \(completed, aborted, imported, pending, running, resuming, canceling, cancelled, pausing, paused, stopping, stopped\). | 


#### Command Example
``` ```

#### Human Readable Output



### tenable-io-add-tags
***
Add tags to Tenable tenant


#### Base Command

`tenable-io-add-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| payload | Payload for REST call | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### tenable-io-resume-scans
***
Resume all scans inputted as an array


#### Base Command

`tenable-io-resume-scans`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanIds | Comma separated scan ID's | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### tenable-io-pause-scans
***
Pauses all scans imputted as ana rray


#### Base Command

`tenable-io-pause-scans`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanIds | Comma separated Scan ID's  | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### tenable-io-launch-scans
***
Launches multiple scans


#### Base Command

`tenable-io-launch-scans`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_ids | Comma separated list of scan ID's | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### tenable-io-create-scan
***
Creates a new scan from a JSON body


#### Base Command

`tenable-io-create-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanSettings | JSON data to build the scan from | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tenable.IO.NewScan.Id | string | ID of the scan that was just created | 
| Tenable.IO.NewScan.ScanIds | string | List of IDs created | 


#### Command Example
``` ```

#### Human Readable Output



### tenable-io-check-temaplates
***
Returns Info about scan templates


#### Base Command

`tenable-io-check-temaplates`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| templates | unknown | The temaplates | 


#### Command Example
``` ```

#### Human Readable Output


