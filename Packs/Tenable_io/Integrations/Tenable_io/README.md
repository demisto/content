A comprehensive asset-centric solution to accurately track resources while accommodating dynamic assets such as cloud, mobile devices, containers, and web applications.
This integration was integrated and tested with January 2023 release of Tenable.io.

## Configure Tenable Vulnerability Management on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Tenable Vulnerability Management.
 Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | URL | Tenable URL. | True |
    | Access Key | Tenable API access key. | True |
    | Secret Key | Tenable API secret key. | True |
    | Events Fetch Interval | Fetch interval in minutes for events. | False |
    | Assets Fetch Interval | Fetch interval in minutes for assets and vulnerabilities. | False |
    | Severity | The severity of the vulnerabilities to include in the export. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Max Fetch | The maximum number of audit logs to retrieve for each event type. For more information about event types see the help section. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Permissions

| **Command Name**                        | **Required Permissions**                                                       |
|-----------------------------------------|--------------------------------------------------------------------------------|
| tenable-io-list-scans                   | BASIC [16] user permissions and CAN VIEW [16] scan permissions.                |
| tenable-io-launch-scan                  | SCAN OPERATOR [24] user permissions.                                           |
| tenable-io-get-scan-report              | BASIC [16] user permissions.                                                   |
| tenable-io-get-vulnerability-details    | BASIC [16] user permissions.                                                   |
| tenable-io-get-vulnerabilities-by-asset | BASIC [16] user permissions.                                                   |
| tenable-io-get-scan-status              | BASIC [16] user permissions and CAN VIEW [16] scan permissions.                |
| tenable-io-resume-scan                  | SCAN OPERATOR [24] user permissions and CAN EXECUTE [32] scan permissions.     |
| tenable-io-pause-scan                   | SCAN OPERATOR [24] user permissions and CAN EXECUTE [32] scan permissions.     |
| tenable-io-get-asset-details            | BASIC [16] user permissions.                                                   |
| tenable-io-export-assets                | ADMINISTRATOR [64] user permissions.                                           |
| tenable-io-export-vulnerabilities       | ADMINISTRATOR [64] user permissions.                                           |
| tenable-io-list-scan-filters            | BASIC [16] user permissions                                                    |
| tenable-io-get-scan-history             | SCAN OPERATOR [24] user permissions and CAN VIEW [16] scan permissions         |
| tenable-io-export-scan                  | SCAN OPERATOR [24] user permissions and CAN VIEW [16] scan permissions         |




## Concurrency Limits

| **Limitations**                                                                                                                                                           | **Commands name**                                                                                                                                                                                                                                                                  |
|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Three concurrent requests per Tenable.io customer instance.<br>Note: This limit is subject to change.                                                                     | tenable-io-list-scans<br>tenable-io-launch-scan<br>tenable-io-get-scan-report<br>tenable-io-get-vulnerability-details<br>tenable-io-get-vulnerabilities-by-asset <br>tenable-io-get-scan-status<br>tenable-io-resume-scan<br>tenable-io-pause-scan<br>tenable-io-get-asset-details |
| Two concurrent asset exports per container. Tenable.io also prevents duplicate exports from running concurrently. <br>For example, export requests with the same filters. | tenable-io-export-assets<br>tenable-io-export-vulnerabilities                                                                                                                                                                                                                      |

## Notes:
- ***Fetch assets and vulnerabilities (Beta)*** command fetches assets and vulnerabilities from the last 90 days only.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### tenable-io-list-scans

***
Retrieves scans from the Tenable platform.


#### Base Command

`tenable-io-list-scans`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| folderId | The ID of the folder whose scans should be listed. Scans are stored<br/>in specific folders on Tenable, e.g.: folderId=8. | Optional | 
| lastModificationDate | Limit the results to those that have only changed since this time. Date format will be YYYY-MM-DD format or relational expressions like “7 days ago”. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | number | The unique ID of the scan. | 
| TenableIO.Scan.Name | string | The name of the scan. | 
| TenableIO.Scan.Target | string | The targets to scan. | 
| TenableIO.Scan.Status | string | The status of the scan \(completed, aborted, imported, pending, running, resuming, canceling, cancelled, pausing, paused, stopping, stopped\). | 
| TenableIO.Scan.StartTime | date | The scheduled start time for the scan. | 
| TenableIO.Scan.EndTime | date | The scheduled end time for the scan. | 
| TenableIO.Scan.Enabled | boolean | If true, the schedule for the scan is enabled. | 
| TenableIO.Scan.Type | string | The type of scan \(local, remote, or agent\). | 
| TenableIO.Scan.Owner | string | The owner of the scan. | 
| TenableIO.Scan.Scanner | string | The scanner assigned for the scan. | 
| TenableIO.Scan.Policy | string | The policy assigned for the scan. | 
| TenableIO.Scan.CreationDate | date | The creation date for the scan in Unix time. | 
| TenableIO.Scan.LastModificationDate | date | The last modification date for the scan in Unix time. | 
| TenableIO.Scan.FolderId | number | The unique ID of the folder where the scan has been stored. | 

#### Command example

```!tenable-io-list-scans ```

#### Context Example

```json
{
    "TenableIO": {
        "Scan": [
            {
                "CreationDate": "2024-11-07T11:11:05Z",
                "Enabled": false,
                "EndTime": "2024-11-07T11:11:05Z",
                "FolderId": 5,
                "Id": 10,
                "LastModificationDate": "2024-05-07T11:11:05Z",
                "Name": "some_name",
                "Owner": "some_owner",
                "Policy": "Host Discovery",
                "StartTime": "2024-11-07T11:11:05Z",
                "Status": "aborted",
                "Targets": "1.1.1.1, 0.0.0.0",
                "Type": "remote"
            },
        ]
    }
}
```

#### Human Readable Output

>### Tenable.io - List of Scans

>|FolderId|Id|Name|Targets|Status|StartTime|EndTime|Enabled|Type|Owner|Scanner|Policy|CreationDate|LastModificationDate|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 5 | 10 | some_name | 1.1.1.1, 0.0.0.0 | aborted | Thu Nov 07 11:11:05 2024 | Thu Nov 07 11:11:05 2024 | false | remote | some_owner |  | Host Discovery | Thu Nov 07 11:11:05 2024 | Thu Nov 07 11:11:05 2024 |


### tenable-io-launch-scan

***
Launches a scan with existing or custom targets. You can specify custom targets in the command arguments.

#### Base Command

`tenable-io-launch-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The ID of the scan to launch. | Required | 
| scanTargets | If specified, targets to be scanned instead of the default. This value can be an array where each index is a target, or an array with a single index of comma-separated targets. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | number | The unique ID of the scan. | 
| TenableIO.Scan.Targets | string | The targets to scan. | 
| TenableIO.Scan.Status | string | The status of the scan \(completed, aborted, imported, pending, running, resuming, canceling, cancelled, pausing, paused, stopping, stopped\). | 

#### Command example

```!tenable-io-launch-scan scanId="10"```

#### Context Example

```json
{
    "TenableIO": {
        "Scan": {
            "Id": "10",
            "Status": "pending",
            "Targets": "target_1,target_2,target_3"
        }
    }
}
```

>### The requested scan was launched successfully

>|Id|Targets|Status|
>|---|---|---|
>| 10 | target_1,target_2,target_3 | pending |


### tenable-io-get-scan-report

***
Retrieves a scan report for the specified scan.

#### Base Command

`tenable-io-get-scan-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The ID of the scan to retrieve. | Required | 
| detailed | If true, the report will contain remediation and host information for the specified scan. Otherwise, the report will only contain vulnerabilities. Possible values: "yes" and "no". Possible values are: yes, no. Default is no. | Optional | 
| info | Whether to return the basic details of the specified scan. Possible values: "yes" and "no". Possible values are: yes, no. Default is no. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | number | The unique ID of the scan. | 
| TenableIO.Scan.Name | string | The name of the scan. | 
| TenableIO.Scan.Targets | string | The targets to scan. | 
| TenableIO.Scan.Status | string | The status of the scan \("completed", "aborted", "imported", "pending", "running", "resuming", "canceling", "cancelled", "pausing", "paused", "stopping", "stopped"\). | 
| TenableIO.Scan.StartTime | string | The scheduled start time for the scan. | 
| TenableIO.Scan.EndTime | string | The scheduled end time for the scan. | 
| TenableIO.Scan.Scanner | string | The scanner assigned for the scan. | 
| TenableIO.Scan.Policy | string | The policy assigned to the scan. | 
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
| TenableIO.Remediations.Id | string | The unique ID of the remediation. | 
| TenableIO.Remediations.Description | string | Specific information related to the vulnerability and steps to remediate. | 
| TenableIO.Remediations.AffectedHosts | number | The number of hosts affected. | 
| TenableIO.Remediations.AssociatedVulnerabilities | number | The number of vulnerabilities associated with the remedy. | 

#### Command example

```!tenable-io-get-scan-report scanId="10"```

#### Context Example

```json
{
    "TenableIO": {
        "Vulnerabilities": [
            {
                "Description": "description",
                "FirstSeen": "2024-11-07T11:11:05Z",
                "Id": 00000,
                "LastSeen": "2024-11-07T11:11:05Z",
                "Name": "some_name",
                "Severity": "None",
                "Solution": "Solution",
                "Synopsis": "Synopsis",
                "VulnerabilityOccurences": 26
            },
            {
                "Description": "description",
                "FirstSeen": "2024-11-07T11:11:05Z",
                "Id": 11111,
                "LastSeen": "2024-11-07T11:11:05Z",
                "Name": "some_name",
                "Severity": "None",
                "Synopsis": "Synopsis",
                "VulnerabilityOccurences": 12
            },
        ]
    }
}
```

#### Human Readable Output

>### Vulnerabilities

>|Id|Name|Severity|Description|Synopsis|Solution|FirstSeen|LastSeen|VulnerabilityOccurences|
>|---|---|---|---|---|---|---|---|---|
>| 00000 | some_name | None | description | Synopsis | Solution | 2024-11-07T11:11:05Z | 2024-11-07T11:11:05Z | 26 |
>| 11111 | some_name | None | description | Synopsis |  | 2024-11-07T11:11:05Z | 2024-11-07T11:11:05Z | 12 |
>

### tenable-io-get-vulnerability-details

***
Retrieves details for the specified vulnerability.


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

#### Command example

```!tenable-io-get-vulnerability-details vulnerabilityId=fake_id```

#### Context Example

```json
{
    "TenableIO": {
        "Vulnerabilities": {
            "Description": "Description",
            "Family": "General",
            "FirstSeen": "2024-11-07T11:11:05Z",
            "LastSeen": "2024-11-07T11:11:05Z",
            "ModificationDate": "2024-11-07T11:11:05Z",
            "Name": "Name",
            "PublicationDate": "2024-11-07T11:11:05Z",
            "Severity": "None",
            "Synopsis": "Synopsis",
            "Type": "remote",
            "VulnerabilityOccurences": 1
        }
    }
}
```

#### Human Readable Output

>### Vulnerability details - fake_id

>|Name|Severity|Type|Family|Description|Synopsis|FirstSeen|LastSeen|PublicationDate|ModificationDate|VulnerabilityOccurences|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Name | None | remote | General | Description | Synopsis | 2024-11-07T11:11:05Z | 2024-11-07T11:11:05Z | 2024-11-07T11:11:05Z | 2024-11-07T11:11:05Z | 1 |


### tenable-io-get-vulnerabilities-by-asset

***
Gets a list of up to 5000 of the vulnerabilities recorded for a specified asset.

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
| TenableIO.Assets.Vulnerabilities | number | A list of all the vulnerability IDs associated with the asset. | 
| TenableIO.Vulnerabilities.Id | number | The vulnerability unique ID. | 
| TenableIO.Vulnerabilities.Name | string | The name of the vulnerability. | 
| TenableIO.Vulnerabilities.Severity | number | Integer \[0-4\] indicating how severe the vulnerability is, where 0 is info only. | 
| TenableIO.Vulnerabilities.Family | string | The vulnerability family. | 
| TenableIO.Vulnerabilities.VulnerabilityOccurences | number | The number of times the vulnerability was found. | 
| TenableIO.Vulnerabilities.VulnerabilityState | string | The current state of the reported vulnerability \("Active", "Fixed", "New", etc.\). | 

#### Command example

```!tenable-io-get-vulnerabilities-by-asset hostname="debian8628.aspadmin.net"```

#### Context Example

```json
{
    "TenableIO": {
        "Assets": {
            "Hostname": "debian8628.aspadmin.net",
            "Vulnerabilities": [
                11111,
                22222,
            ]
        },
        "Vulnerabilities": [
            {
                "Family": "General",
                "Id": 11111,
                "Name": "Name_01",
                "Severity": "None",
                "VulnerabilityOccurences": 2,
                "VulnerabilityState": "Active"
            },
            {
                "Family": "General",
                "Id": 22222,
                "Name": "Name_02",
                "Severity": "None",
                "VulnerabilityOccurences": 2,
                "VulnerabilityState": "Active"
            },
        ]
    }
}
```

#### Human Readable Output

>### Vulnerabilities for asset debian8628.aspadmin.net

>|Id|Name|Severity|Family|VulnerabilityOccurences|VulnerabilityState|
>|---|---|---|---|---|---|
>| 11111 | Name_01 | None | General | 2 | Active |
>| 22222 | Name_02 | None | General | 2 | Active |


### tenable-io-get-scan-status

***
Checks the status of a specific scan using the scan ID. Possible values: "Running", "Completed", and "Empty" (Ready to run).


#### Base Command

`tenable-io-get-scan-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The unique ID of the scan. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | string | The unique ID of the scan specified. | 
| TenableIO.Scan.Status | string | The status of the scan specified. | 

#### Command example

```!tenable-io-get-scan-status scanId="10"```

#### Context Example

```json
{
    "TenableIO": {
        "Scan": {
            "Id": "10",
            "Status": "aborted"
        }
    }
}
```

#### Human Readable Output

>### Scan status for 10

>|Id|Status|
>|---|---|
>| 10 | aborted |


### tenable-io-resume-scan

***
Resumes all scans inputted as an array. Will resume scans whose status is 'Paused'.

#### Base Command

`tenable-io-resume-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | Comma-separated list of scan IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | String | The unique ID of the scan. | 
| TenableIO.Scan.Status | String | The status of the scan \(completed, aborted, imported, pending, running, resuming, canceling, cancelled, pausing, paused, stopping, stopped\). | 

#### Command example

```!tenable-io-resume-scan scanId="13"```

#### Context Example

```json
{
    "TenableIO": {
        "Scan": {
            "Id": "13",
            "Status": "Resuming"
        }
    }
}
```

#### Human Readable Output

>### The requested scan was resumed successfully

>|Id|Status|
>|---|---|
>| 13 | Resuming |


### tenable-io-pause-scan

***
Pauses all scans inputted as an array. Will pause scans whose status is 'Running'.

#### Base Command

`tenable-io-pause-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | Comma-separated list of scan IDs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.Id | String | The unique id of the scan. | 
| TenableIO.Scan.Status | String | The status of the scan \(completed, aborted, imported, pending, running, resuming, canceling, cancelled, pausing, paused, stopping, stopped\). | 

#### Command example

```!tenable-io-pause-scan scanId="10"```

#### Context Example

```json
{
    "TenableIO": {
        "Scan": {
            "Id": "10",
            "Status": "Pausing"
        }
    }
}
```

#### Human Readable Output

>### The requested scan was paused successfully

>|Id|Status|
>|---|---|
>| 13 | Pausing |


### tenable-io-get-asset-details

***
Retrieves details for the specified asset including custom attributes.


#### Base Command

`tenable-io-get-asset-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP Address of the asset. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.AssetDetails.attributes | unknown | Array of custom attributes of asset. | 
| TenableIO.AssetDetails.counts | unknown | Array of audit statuses and vulnerabilities by type. | 
| TenableIO.AssetDetails.created_at | date | Date asset was created. | 
| TenableIO.AssetDetails.first_seen | date | Date asset was first seen. | 
| TenableIO.AssetDetails.fqdn | unknown | Array of fully-qualified domain names. | 
| TenableIO.AssetDetails.id | string | GUID of tenable.io asset. | 
| TenableIO.AssetDetails.interfaces | unknown | Array of interface information. | 
| TenableIO.AssetDetails.ipv4 | unknown | Array of IPv4 addresses. | 
| TenableIO.AssetDetails.operating_system | unknown | Array of operating systems. | 
| TenableIO.AssetDetails.tags | unknown | Array of tags added to asset. | 
| TenableIO.AssetDetails.updated_at | date | Date the asset was last updated. | 

#### Command example

```!tenable-io-get-asset-details ip=1.3.2.1"```

#### Context Example

```json
{
    "TenableIO": {
        "AssetDetails": {
            "agent_name": [],
            "attributes": [],
            "aws_availability_zone": [],
            "aws_ec2_instance_ami_id": [],
            "aws_ec2_instance_group_name": [],
            "aws_ec2_instance_id": [],
            "aws_ec2_instance_state_name": [],
            "aws_ec2_instance_type": [],
            "aws_ec2_name": [],
            "aws_ec2_product_code": [],
            "aws_owner_id": [],
            "aws_region": [],
            "aws_subnet_id": [],
            "aws_vpc_id": [],
            "azure_location": [],
            "azure_resource_group": [],
            "azure_resource_id": [],
            "azure_subscription_id": [],
            "azure_type": [],
            "azure_vm_id": [],
            "bigfix_asset_id": [],
            "bios_uuid": [],
            "counts": {
                "audits": {
                    "statuses": [
                        {
                            "count": 0,
                            "level": 1,
                            "name": "Passed"
                        },
                        {
                            "count": 0,
                            "level": 2,
                            "name": "Warning"
                        },
                        {
                            "count": 0,
                            "level": 3,
                            "name": "Failed"
                        }
                    ],
                    "total": 0
                },
                "vulnerabilities": {
                    "severities": [
                        {
                            "count": 17,
                            "level": 0,
                            "name": "Info"
                        },
                        {
                            "count": 0,
                            "level": 1,
                            "name": "Low"
                        },
                        {
                            "count": 0,
                            "level": 2,
                            "name": "Medium"
                        },
                        {
                            "count": 0,
                            "level": 3,
                            "name": "High"
                        },
                        {
                            "count": 1,
                            "level": 4,
                            "name": "Critical"
                        }
                    ],
                    "total": 18
                }
            },
            "created_at": "2024-11-07T11:11:05Z",
            "exposure_confidence_value": null,
            "first_seen": "2024-11-07T11:11:05Z",
            "fqdn": [
                "test.com"
            ],
            "gcp_instance_id": [],
            "gcp_project_id": [],
            "gcp_zone": [],
            "has_agent": false,
            "hostname": [
                "test.com"
            ],
            "id": "fake_asset_id",
            "installed_software": [
                "cpe:/a:test:0.0.0",
            ],
            "interfaces": [
                {
                    "fqdn": [
                        "test.com"
                    ],
                    "ipv4": [
                        "1.3.2.1"
                    ],
                    "ipv6": [],
                    "mac_address": [],
                    "name": "UNKNOWN"
                }
            ],
            "ipv4": [
                "1.3.2.1"
            ],
            "ipv6": [],
            "last_authenticated_scan_date": null,
            "last_licensed_scan_date": "2024-11-07T11:11:05Z",
            "last_scan_id": "fake_scan_id",
            "last_scan_target": "test.com'",
            "last_schedule_id": "fake_schedule_id",
            "last_seen": "2024-11-07T11:11:05Z",
            "mac_address": [],
            "mcafee_epo_agent_guid": [],
            "mcafee_epo_guid": [],
            "netbios_name": [],
            "network_name": "Default",
            "operating_system": [
                "Linux Kernel 2.6"
            ],
            "qualys_asset_id": [],
            "qualys_host_id": [],
            "security_protection_level": null,
            "security_protections": [],
            "servicenow_sysid": [],
            "sources": [
                {
                    "first_seen": "2024-11-07T11:11:05.739Z",
                    "last_seen": "2024-11-07T11:11:05.739Z",
                    "name": "name"
                }
            ],
            "ssh_fingerprint": [],
            "system_type": [
                "general-purpose"
            ],
            "tags": [
                {
                    "added_at": "2024-11-07T11:11:05Z",
                    "added_by": "fake_id",
                    "source": "static",
                    "tag_key": "some_key",
                    "tag_uuid": "fake_uuid",
                    "tag_value": "test.com"
                }
            ],
            "tenable_uuid": [],
            "time_end": "2024-11-07T11:11:05Z",
            "time_start": "2024-11-07T11:11:05Z",
            "updated_at": "2024-11-07T11:11:05Z",
            "uuid": "fake_asset_id"
        }
    }
}
```

#### Human Readable Output

>### Asset Info for 1.3.2.1

>|attributes|fqdn|interfaces|ipv4|id|last_seen|
>|---|---|---|---|---|---|
>|  | test.com | {'name': 'UNKNOWN', 'fqdn': ['test.com'], 'mac_address': [], 'ipv4': ['1.3.2.1'], 'ipv6': []} | 1.3.2.1 | fake_asset_id | 2024-11-07T11:11:05.739Z |


### tenable-io-export-assets

***
Retrieves details for the specified asset to include custom attributes.

## Limitations
When inserting invalid arguments, an error message could be returned.

#### Base Command

`tenable-io-export-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| chunkSize | Specifies the number of assets per exported chunk. The range is 100-10000. Default is 100. | Optional | 
| intervalInSeconds | The number of seconds until the next run. Default is 10. | Optional | 
| timeOut | The timeout for the polling in seconds. Default is 600. | Optional | 
| createdAt | When specified, the results returned in the list are limited to assets created later than the date specified. Date format will be epoch date format or relational expressions like “7 days ago”.'. | Optional | 
| updatedAt | When specified, the results returned in the list are limited to assets updated later than the date specified. Date format will be epoch date format or relational expressions like “7 days ago”.'. | Optional | 
| terminatedAt | When specified, the results returned in the list are limited to assets terminated later than the date specified. Date format will be epoch date format or relational expressions like “7 days ago”.'. | Optional | 
| isTerminated | When set to true, returns assets which have any value for the terminatedAt attribute. | Optional | 
| deletedAt | When specified, the results returned in the list are limited to assets deleted later than the date specified. Date format will be epoch date format or relational expressions like “7 days ago”.'. | Optional | 
| isDeleted | When set to true, returns assets which have any value for the deletedAt attribute. Possible values are: true, false. | Optional | 
| isLicensed | Specifies whether the asset is included in the asset count for the Tenable.io instance. If true, returns only licensed assets. If false, returns only unlicensed assets. Possible values are: true, false. | Optional | 
| firstScanTime | When specified, the results returned in the list are limited to assets with a first scan time later than the date specified. Date format will be epoch date format or relational expressions like “7 days ago”.'. | Optional | 
| lastAuthenticatedScanTime | When specified, the results returned in the list are limited to assets with a last credentialed scan time later than the date specified. Date format will be epoch date format or relational expressions like “7 days ago”.'. | Optional | 
| lastAssessed | When specified, the results returned in the list are limited to assets with a last assessed time later than the date specified. Date format will be epoch date format or relational expressions like “7 days ago”.'. | Optional | 
| serviceNowSysId | If true, returns all assets that have a ServiceNow Sys ID, regardless of value. If false, returns all assets that do not have a ServiceNow Sys ID. Possible values are: true, false. | Optional | 
| sources | A comma-separated list of sources. Possible values are: AWS, NESSUS_AGENT, PVS,NESSUS_SCAN, WAS. When specified, the results returned in the list are limited to assets that have the specified source. | Optional | 
| hasPluginResults | If true, returns all assets that have a plugin results associated with it. Possible values are: true, false. | Optional | 
| tagCategory | When specified, the results returned in the list are limited to assets with the specified tag category. | Optional | 
| tagValue | When specified, the results returned in the list are limited to assets with the specified tag value. | Optional | 
| exportUuid | The export uuid. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Asset.id | String | The UUID of the asset in Tenable.io. Use this value as the unique key for the asset. | 
| TenableIO.Asset.has_agent | Boolean | Specifies whether a Nessus agent scan identified the asset. | 
| TenableIO.Asset.has_plugin_results | Boolean | Specifies whether the asset has plugin results associated with it. | 
| TenableIO.Asset.created_at | Date | The time and date when Tenable.io created the asset record. | 
| TenableIO.Asset.terminated_at | Date | The time and date when a user terminated the Amazon Web Service \(AWS\) virtual machine instance of the asset. | 
| TenableIO.Asset.terminated_by | String | The user who terminated the AWS instance of the asset. | 
| TenableIO.Asset.updated_at | Date | The time and date when the asset record was last updated. | 
| TenableIO.Asset.deleted_at | Date | The time and date when a user deleted the asset record. When a user deletes an asset record, Tenable.io retains the record until the asset ages out of the license count. | 
| TenableIO.Asset.deleted_by | String | The user who deleted the asset record. | 
| TenableIO.Asset.first_seen | Date | The time and date when a scan first identified the asset. | 
| TenableIO.Asset.last_seen | Date | The time and date of the scan that most recently identified the asset. | 
| TenableIO.Asset.first_scan_time | Date | The time and date of the first scan run against the asset. | 
| TenableIO.Asset.last_scan_time | Date | The time and date of the last scan run against the asset. | 
| TenableIO.Asset.last_authenticated_scan_date | Date | The time and date of the last credentialed scan run on the asset. | 
| TenableIO.Asset.last_licensed_scan_date | Date | The time and date of the last scan that identified the asset as licensed. Tenable.io categorizes an asset as licensed if a scan of that asset has returned results from a non-discovery plugin within the last 90 days. | 
| TenableIO.Asset.last_scan_id | String | The UUID of the scan configuration used during the last scan of the asset. | 
| TenableIO.Asset.last_schedule_id | String | The schedule id for the last scan of the asset. | 
| TenableIO.Asset.azure_vm_id | String | The unique identifier of the Microsoft Azure virtual machine instance. For more information, see "Accessing and Using Azure VM Unique ID" in the Microsoft Azure documentation. | 
| TenableIO.Asset.azure_resource_id | String | The unique identifier of the resource in the Azure Resource Manager. For more information, see the Azure Resource Manager Documentation. | 
| TenableIO.Asset.gcp_project_id | String | The unique identifier of the virtual machine instance in Google Cloud Platform \(GCP\). | 
| TenableIO.Asset.gcp_zone | String | The customized name of the project to which the virtual machine instance belongs in GCP. For more information see "Creating and Managing Projects" in the GCP documentation. | 
| TenableIO.Asset.gcp_instance_id | String | The zone where the virtual machine instance runs in GCP. For more information, see "Regions and Zones" in the GCP documentation. | 
| TenableIO.Asset.aws_ec2_instance_ami_id | String | The unique identifier of the Linux AMI image in Amazon Elastic Compute Cloud \(Amazon EC2\). For more information, see the Amazon Elastic Compute Cloud Documentation. | 
| TenableIO.Asset.aws_ec2_instance_id | String | The unique identifier of the Linux instance in Amazon EC2. For more information, see the Amazon Elastic Compute Cloud Documentation. | 
| TenableIO.Asset.agent_uuid | String | The unique identifier of the Nessus agent that identified the asset. | 
| TenableIO.Asset.bios_uuid | String | The BIOS UUID of the asset. | 
| TenableIO.Asset.network_id | String | The ID of the network object associated with scanners that identified the asset. | 
| TenableIO.Asset.network_name | String | The ID of the network object associated with scanners that identified the asset. | 
| TenableIO.Asset.aws_owner_id | String | The canonical user identifier for the AWS account associated with the virtual machine instance. | 
| TenableIO.Asset.aws_availability_zone | String | The availability zone where Amazon Web Services hosts the virtual machine instance. | 
| TenableIO.Asset.aws_region | String | The region where AWS hosts the virtual machine instance. | 
| TenableIO.Asset.aws_vpc_id | String | The unique identifier for the virtual public cloud that hosts the AWS virtual machine instance. | 
| TenableIO.Asset.aws_ec2_instance_group_name | String | The virtual machine instance's group in AWS. | 
| TenableIO.Asset.aws_ec2_instance_state_name | String | The state of the virtual machine instance in AWS at the time of the scan. | 
| TenableIO.Asset.aws_ec2_instance_type | String | The type of instance in AWS EC2. | 
| TenableIO.Asset.aws_subnet_id | String | The unique identifier of the AWS subnet where the virtual machine instance was running at the time of the scan. | 
| TenableIO.Asset.aws_ec2_product_code | String | The product code associated with the AMI used to launch the virtual machine instance in AWS EC2. | 
| TenableIO.Asset.aws_ec2_name | String | The name of the virtual machine instance in AWS EC2. | 
| TenableIO.Asset.mcafee_epo_guid | String | The unique identifier of the asset in McAfee ePolicy Orchestrator \(ePO\). | 
| TenableIO.Asset.mcafee_epo_agent_guid | String | The unique identifier of the McAfee ePO agent that identified the asset. | 
| TenableIO.Asset.servicenow_sysid | String | The unique record identifier of the asset in ServiceNow. | 
| TenableIO.Asset.bigfix_asset_id | String | The unique identifiers of the asset in HCL BigFix. | 
| TenableIO.Asset.agent_names | String | The names of any Nessus agents that scanned and identified the asset. | 
| TenableIO.Asset.installed_software | String | A list of Common Platform Enumeration \(CPE\) values that represent software applications a scan identified as present on an asset. | 
| TenableIO.Asset.ipv4s | String | The IPv4 addresses that scans have associated with the asset record. | 
| TenableIO.Asset.ipv6s | String | The IPv6 addresses that scans have associated with the asset record. | 
| TenableIO.Asset.fqdns | String | The fully-qualified domain names that scans have associated with the asset record. | 
| TenableIO.Asset.mac_addresses | String | The MAC addresses that scans have associated with the asset record. | 
| TenableIO.Asset.netbios_names | String | The NetBIOS names that scans have associated with the asset record. | 
| TenableIO.Asset.operating_systems | String | The operating systems that scans have associated with the asset record. | 
| TenableIO.Asset.system_types | String | The system types as reported by Plugin ID 54615. Possible values include router, general-purpose, scan-host, and embedded. | 
| TenableIO.Asset.hostnames | String | The hostnames that scans have associated with the asset record. | 
| TenableIO.Asset.ssh_fingerprints | String | The SSH key fingerprints that scans have associated with the asset record. | 
| TenableIO.Asset.qualys_asset_ids | String | The Asset ID of the asset in Qualys. For more information, see the Qualys documentation. | 
| TenableIO.Asset.qualys_host_ids | String | The Host ID of the asset in Qualys. For more information, see the Qualys documentation. | 
| TenableIO.Asset.manufacturer_tpm_ids | String | The manufacturer's unique identifiers of the Trusted Platform Module \(TPM\) associated with the asset. | 
| TenableIO.Asset.symantec_ep_hardware_keys | String | The hardware keys for the asset in Symantec Endpoint Protection. | 
| TenableIO.Asset.sources.name | String | The name of the entity that reported the asset details. Sources can include sensors, connectors, and API imports. | 
| TenableIO.Asset.sources.first_seen | Date | The ISO timestamp when the source first reported the asset. | 
| TenableIO.Asset.sources.last_seen | Date | The ISO timestamp when the source last reported the asset. | 
| TenableIO.Asset.tags.uuid | String | The UUID of the tag. | 
| TenableIO.Asset.tags.key | String | The tag category \(the first half of the category:value pair\). | 
| TenableIO.Asset.tags.value | String | The tag value \(the second half of the category:value pair\). | 
| TenableIO.Asset.tags.added_by | String | The UUID of the user who assigned the tag to the asset. | 
| TenableIO.Asset.tags.added_at | Date | The ISO timestamp when the tag was assigned to the asset. | 
| TenableIO.Asset.network_interfaces.name | String | The name of the interface. | 
| TenableIO.Asset.network_interfaces.mac_address | String | The MAC addresses of the interface. | 
| TenableIO.Asset.network_interfaces.ipv6 | String | One or more IPv6 addresses belonging to the interface. | 
| TenableIO.Asset.network_interfaces.fqdns | String | One or more FQDNs belonging to the interface. | 
| TenableIO.Asset.network_interfaces.ipv4s | String | One or more IPv4 addresses belonging to the interface. | 
| TenableIO.Asset.acr_score | String | The Asset Criticality Rating \(ACR\) for the asset. | 
| TenableIO.Asset.exposure_score | String | The Asset Exposure Score \(AES\) for the asset. | 

#### Command example

```!tenable-io-export-assets chunkSize=500```

#### Context Example

```json
{
    "TenableIO": {
        "Asset": [
            {
                "created_at": "2024-11-07T11:11:05Z",
                "first_scan_time": "2024-11-07T11:11:05Z",
                "first_seen": "2024-11-07T11:11:05Z",
                "fqdns": [
                    "test.com"
                ],
                "has_agent": false,
                "has_plugin_results": true,
                "hostnames": [
                    "test.com"
                ],
                "id": "fake_uuid",
                "installed_software": [],
                "ipv4s": [
                    "1.3.2.1"
                ],
                "last_licensed_scan_date": "2024-11-07T11:11:05Z",
                "last_scan_id": "fake_uuid",
                "last_scan_time": "2024-11-07T11:11:05Z",
                "last_schedule_id": "fake_uuid",
                "last_seen": "2024-11-07T11:11:05Z",
                "network_id": "00000000-0000-0000-0000-000000000000",
                "network_interfaces": [
                    {
                        "aliased": null,
                        "fqdns": [
                            "test.com"
                        ],
                        "ipv4s": [
                            "1.3.2.1"
                        ],
                        "ipv6s": [],
                        "mac_addresses": [],
                        "name": "UNKNOWN",
                        "virtual": null
                    }
                ],
                "network_name": "Default",
                "operating_systems": [
                    "Linux Kernel 2.6"
                ],
                "sources": [
                    {
                        "first_seen": "2024-11-07T11:11:05Z",
                        "last_seen": "2024-11-07T11:11:05Z",
                        "name": "NESSUS_SCAN"
                    }
                ],
                "system_types": [
                    "general-purpose"
                ],
                "tags": [
                    {
                        "added_at": "2024-11-07T11:11:05Z",
                        "added_by": "fake_uuid",
                        "key": "some_key",
                        "uuid": "fake_uuid",
                        "value": "test.com"
                    }
                ],
                "updated_at": "2024-11-07T11:11:05Z"
            },
            {
                "created_at": "2024-11-07T11:11:05Z",
                "first_scan_time": "2024-11-07T11:11:05Z",
                "first_seen": "2024-11-07T11:11:05Z",
                "fqdns": [
                    "test.net"
                ],
                "has_agent": false,
                "has_plugin_results": true,
                "hostnames": [
                    "test.net"
                ],
                "id": "fake_uuid",
                "installed_software": [],
                "ipv4s": [
                    "1.3.2.1"
                ],
                "last_licensed_scan_date": "2024-11-07T11:11:05Z",
                "last_scan_id": "fake_uuid",
                "last_scan_time": "2024-11-07T11:11:05Z",
                "last_schedule_id": "fake_uuid",
                "last_seen": "2024-11-07T11:11:05Z",
                "network_id": "00000000-0000-0000-0000-000000000000",
                "network_interfaces": [
                    {
                        "aliased": null,
                        "fqdns": [
                            "test.net"
                        ],
                        "ipv4s": [
                            "1.3.2.1"
                        ],
                        "ipv6s": [],
                        "mac_addresses": [],
                        "name": "UNKNOWN",
                        "virtual": null
                    }
                ],
                "network_name": "Default",
                "operating_systems": [
                    "Linux Kernel 2.6"
                ],
                "sources": [
                    {
                        "first_seen": "2024-11-07T11:11:05Z",
                        "last_seen": "2024-11-07T11:11:05Z",
                        "name": "NESSUS_SCAN"
                    }
                ],
                "ssh_fingerprints": [
                    "fake_ssh_fingerprints"
                ],
                "system_types": [
                    "general-purpose"
                ],
                "tags": [
                    {
                        "added_at": "2024-11-07T11:11:05Z",
                        "added_by": "fake_uuid",
                        "key": "some_key",
                        "uuid": "fake_uuid",
                        "value": "test.com"
                    }
                ],
                "updated_at": "2024-11-07T11:11:05Z"
            },
        ]
    }
}
```

#### Human Readable Output

>### Export Assets Results:

>|ASSET ID|DNS NAME (FQDN)|SYSTEM TYPE|OPERATING SYSTEM|IPV4 ADDRESS|NETWORK|FIRST SEEN|LAST SEEN|LAST LICENSED SCAN|SOURCE|TAGS|
>|---|---|---|---|---|---|---|---|---|---|---|
>| fake_uuid | test.com | general-purpose | Linux Kernel 2.6 | 1.3.2.1 | Default | 2024-11-07T11:11:05Z | 2024-11-07T11:11:05Z | 2024-11-07T11:11:05Z | NESSUS_SCAN | some_key:test.com |
>| fake_uuid | test.net | general-purpose | Linux Kernel 2.6 | 1.3.2.1 | Default | 2024-11-07T11:11:05Z | 2024-11-07T11:11:05Z | 2024-11-07T11:11:05Z | NESSUS_SCAN | some_key:test.com |


### tenable-io-export-vulnerabilities

***
Retrieves details for the specified asset to include custom attributes.


## Limitations
When inserting invalid arguments, an error message could be returned.


#### Base Command

`tenable-io-export-vulnerabilities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| numAssets | The number of assets used to chunk the vulnerabilities. The range for number of assets in a chunk is 50-5000. Default is 50. | Optional | 
| intervalInSeconds | The number of seconds until the next run. Default is 10. | Optional | 
| timeOut | The timeout for the polling in seconds. Default is 600. | Optional | 
| includeUnlicensed | Specifies whether or not to include unlicensed assets. Possible values are: true, false. | Optional | 
| cidrRange | When specified, restricts the search for vulnerabilities to assets assigned an IP address within the specified CIDR range. | Optional | 
| firstFound | When specified, the results returned in the list are limited to vulnerabilities that were first found between the specified date and now. Date format will be epoch date format or relational expressions like “7 days ago”. | Optional | 
| lastFixed | When specified, the results returned in the list are limited to vulnerabilities that were fixed between the specified date and now. Date format will be epoch date format or relational expressions like “7 days ago”. | Optional | 
| lastFound | When specified, the results returned in the list are limited to vulnerabilities that were last found between the specified date and now. Date format will be epoch date format or relational expressions like “7 days ago”. | Optional | 
| networkId | The ID of the network object associated with scanners that detected the vulnerabilities you want to export. | Optional | 
| pluginId | A comma-separated list of plugin IDs for which you want to filter the vulnerabilities. | Optional | 
| pluginType | The plugin type for which you want to filter the vulnerabilities. If not set, export includes all vulnerabilities regardless of plugin type. Possible values are: remote, local, combined, settings, summary, third-party, reputation. | Optional | 
| severity | The severity of the vulnerabilities to include in the export. Defaults to all severity levels. The severity of a vulnerability is defined using the Common Vulnerability Scoring System (CVSS) base score. Supported array values are: info, low, medium, high, critical. | Optional | 
| since | The start date for the range of data you want to export. Date format will be epoch date format or relational expressions like “7 days ago”. Note: This filter cannot be used in conjunction with the firstFound, lastFound, or lastFixed. | Optional | 
| state | A comma-separated list of states of the vulnerabilities you want the export to include. Supported, case-insensitive values are: open, reopened, fixed. This parameter is required if your request includes firstFound, lastFound, or lastFixed parameters. If your request omits this parameter, the export includes default states open and reopened only. | Optional | 
| tagCategory | When specified, the results returned in the list are limited to assets with the specified tag category. | Optional | 
| tagValue | When specified, the results returned in the list are limited to assets with the specified tag value. | Optional | 
| vprScoreOperator | An operator that determines the limitation on Vulnerability Priority Rating (VPR), scores value specified at vprScoreValue argument. Supported values are: equal, not equal, lt-lesser, lte-lesser than or equal , gt-greater than , gte-greater than or equal. Possible values are: gte, gt, lte, lt, equal, not equal. | Optional | 
| vprScoreValue | When specified, the results returned in the list are limited to vulnerabilities with the specified Vulnerability Priority Rating (VPR), score or scores according to the score operator (vprScoreOperator) argument. | Optional | 
| vprScoreRange | When specified, the results returned in the list are limited to vulnerabilities with the specified Vulnerability Priority Rating (VPR) score range. Example value: 2.5-3.5. | Optional | 
| exportUuid | The export UUID. | Optional | 
| should_push_events | Set this argument to True in order to create vulnerabilities, otherwise the command will only display the vulnerabilities. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Vulnerability.asset.agent_uuid | String | The UUID of the agent that performed the scan where the vulnerability was found. | 
| TenableIO.Vulnerability.asset.bios_uuid | String | The BIOS UUID of the asset where the vulnerability was found. | 
| TenableIO.Vulnerability.asset.device_type | String | The type of asset where the vulnerability was found. | 
| TenableIO.Vulnerability.asset.fqdn | String | The fully-qualified domain name of the asset where a scan found the vulnerability. | 
| TenableIO.Vulnerability.asset.hostname | String | The host name of the asset where a scan found the vulnerability. | 
| TenableIO.Vulnerability.asset.uuid | String | The UUID of the asset where a scan found the vulnerability. | 
| TenableIO.Vulnerability.asset.ipv6 | String | The IPv6 address of the asset where a scan found the vulnerability. | 
| TenableIO.Vulnerability.asset.last_authenticated_results | Date | The last date credentials that were used successfully to scan the asset. | 
| TenableIO.Vulnerability.asset.last_unauthenticated_results | Date | The last date when the asset was scanned without using credentials | 
| TenableIO.Vulnerability.asset.mac_address | String | The MAC address of the asset where a scan found the vulnerability. | 
| TenableIO.Vulnerability.asset.netbios_name | String | The NETBIOS name of the asset where a scan found the vulnerability. | 
| TenableIO.Vulnerability.asset.netbios_workgroup | String | The NETBIOS workgroup of the asset where a scan found the vulnerability. | 
| TenableIO.Vulnerability.asset.operating_system | String | The operating system of the asset where a scan found the vulnerability. | 
| TenableIO.Vulnerability.asset.network_id | String | The ID of the network object associated with scanners that identified the asset. | 
| TenableIO.Vulnerability.asset.tracked | Boolean | A value specifying whether Tenable.io tracks the asset in the asset management system. | 
| TenableIO.Vulnerability.output | String | The text output of the Nessus scanner. | 
| TenableIO.Vulnerability.plugin.bid | Number | The Bugtraq ID for the plugin. | 
| TenableIO.Vulnerability.plugin.canvas_package | String | The name of the CANVAS exploit pack that includes the vulnerability. | 
| TenableIO.Vulnerability.plugin.checks_for_default_account | Boolean | A value specifying whether the plugin checks for default accounts. | 
| TenableIO.Vulnerability.plugin.checks_for_malware | Boolean | A value specifying whether the plugin checks for malware. | 
| TenableIO.Vulnerability.plugin.cpe | String | The Common Platform Enumeration \(CPE\) number for the plugin. | 
| TenableIO.Vulnerability.plugin.cve | String | The Common Vulnerability and Exposure \(CVE\) ID for the plugin. | 
| TenableIO.Vulnerability.plugin.cvss3_base_score | Number | The CVSSv3 base score \(intrinsic and fundamental characteristics of a vulnerability that are constant over time and user environments\). | 
| TenableIO.Vulnerability.plugin.cvss3_temporal_score | Number | The CVSSv3 temporal score \(characteristics of a vulnerability that change over time but not among user environments\). | 
| TenableIO.Vulnerability.plugin.cvss3_temporal_vector.exploitability | String | The CVSSv3 Exploit Maturity Code \(E\) for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss3_temporal_vector.remediation_level | String | The CVSSv3 Remediation Level \(RL\) temporal metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss3_temporal_vector.report_confidence | String | The CVSSv3 Report Confidence \(RC\) temporal metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss3_temporal_vector.raw | String | The complete CVSSv3 temporal vector metrics and result values for the vulnerability the plugin covers in a condensed and coded format. | 
| TenableIO.Vulnerability.plugin.cvss3_vector.access_vector | String | The CVSSv3 Attack Vector \(AV\) metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss3_vector.access_complexity | String | The CVSSv3 Access Complexity \(AC\) metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss3_vector.authentication | String | The CVSSv3 Authentication \(Au\) metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss3_vector.confidentiality_impact | String | The CVSSv3 integrity impact metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss3_vector.integrity_impact | String | The CVSSv3 integrity impact metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss3_vector.availability_impact | String | The CVSSv3 availability impact metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss3_vector.raw | String | The complete cvss3_vector metrics and result values for the vulnerability the plugin covers in a condensed and coded format. | 
| TenableIO.Vulnerability.plugin.cvss_temporal_vector.exploitability | String | The CVSSv2 Exploitability \(E\) temporal metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss_temporal_vector.remediation_level | String | The CVSSv2 Remediation Level \(RL\) temporal metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss_temporal_vector.report_confidence | String | The CVSSv2 Report Confidence \(RC\) temporal metric for the vulnerability the plugin covers | 
| TenableIO.Vulnerability.plugin.cvss_temporal_vector.raw | String | The complete CVSS temporal vector metrics and result values for the vulnerability the plugin covers in a condensed and coded format. | 
| TenableIO.Vulnerability.plugin.cvss_vector.access_vector | String | The CVSSv2 Access Vector \(AV\) metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss_vector.access_complexity | String | The CVSSv2 Access Complexity \(AC\) metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss_vector.authentication | String | The CVSSv2 Authentication \(Au\) metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss_vector.confidentiality_impact | String | The CVSSv2 confidentiality impact metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss_vector.integrity_impact | String | The CVSSv2 integrity impact metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss_vector.availability_impact | String | The CVSSv2 availability impact metric for the vulnerability the plugin covers. | 
| TenableIO.Vulnerability.plugin.cvss_vector.raw | String | The complete CVSSv2 vector metrics and result values for the vulnerability the plugin covers in a condensed and coded format. | 
| TenableIO.Vulnerability.plugin.cvss_base_score | Number | The CVSSv2 base score \(intrinsic and fundamental characteristics of a vulnerability that are constant over time and user environments\). | 
| TenableIO.Vulnerability.plugin.cvss_temporal_score | Number | The CVSSv2 temporal score \(characteristics of a vulnerability that change over time but not among user environments\). | 
| TenableIO.Vulnerability.plugin.d2_elliot_name | String | The name of the exploit in the D2 Elliot Web Exploitation framework. | 
| TenableIO.Vulnerability.plugin.description | String | Full text description of the vulnerability. | 
| TenableIO.Vulnerability.plugin.exploit_available | Boolean | A value specifying whether a public exploit exists for the vulnerability. | 
| TenableIO.Vulnerability.plugin.exploit_framework_canvas | Boolean | A value specifying whether an exploit exists in the Immunity CANVAS framework. | 
| TenableIO.Vulnerability.plugin.exploit_framework_core | Boolean | A value specifying whether an exploit exists in the CORE Impact framework. | 
| TenableIO.Vulnerability.plugin.exploit_framework_d2_elliot | Boolean | A value specifying whether an exploit exists in the D2 Elliot Web Exploitation framework. | 
| TenableIO.Vulnerability.plugin.exploit_framework_exploithub | Boolean | A value specifying whether an exploit exists in the ExploitHub framework. | 
| TenableIO.Vulnerability.plugin.exploit_framework_metasploit | Boolean | A value specifying whether an exploit exists in the Metasploit framework. | 
| TenableIO.Vulnerability.plugin.exploitability_ease | String | Description of how easy it is to exploit the issue. | 
| TenableIO.Vulnerability.plugin.exploited_by_malware | Boolean | Whether the vulnerability discovered by this plugin is known to be exploited by malware. | 
| TenableIO.Vulnerability.plugin.exploited_by_nessus | Boolean | A value specifying whether Nessus exploited the vulnerability during the process of identification. | 
| TenableIO.Vulnerability.plugin.exploithub_sku | String | The SKU number of the exploit in the ExploitHub framework. | 
| TenableIO.Vulnerability.plugin.family | String | The family to which the plugin belongs. | 
| TenableIO.Vulnerability.plugin.family_id | Number | The ID of the plugin family. | 
| TenableIO.Vulnerability.plugin.has_patch | Boolean | A value specifying whether the vendor has published a patch for the vulnerability. | 
| TenableIO.Vulnerability.plugin.id | Number | The ID of the plugin that identified the vulnerability. | 
| TenableIO.Vulnerability.plugin.in_the_news | Boolean | A value specifying whether this plugin has received media attention \(for example, ShellShock, Meltdown\). | 
| TenableIO.Vulnerability.plugin.metasploit_name | String | The name of the related exploit in the Metasploit framework. | 
| TenableIO.Vulnerability.plugin.ms_bulletin | String | The Microsoft security bulletin that the plugin covers. | 
| TenableIO.Vulnerability.plugin.name | String | The name of the plugin that identified the vulnerability. | 
| TenableIO.Vulnerability.plugin.patch_publication_date | String | The date on which the vendor published a patch for the vulnerability. | 
| TenableIO.Vulnerability.plugin.modification_date | Date | The date on which the plugin was last modified. | 
| TenableIO.Vulnerability.plugin.publication_date | Date | The date on which the plugin was published. | 
| TenableIO.Vulnerability.plugin.risk_factor | String | The risk factor associated with the plugin. Possible values are: Low, Medium, High, or Critical. | 
| TenableIO.Vulnerability.plugin.see_also | String | Links to external websites that contain helpful information about the vulnerability. | 
| TenableIO.Vulnerability.plugin.solution | String | Remediation information for the vulnerability. | 
| TenableIO.Vulnerability.plugin.stig_severity | String | Security Technical Implementation Guide \(STIG\) severity code for the vulnerability. | 
| TenableIO.Vulnerability.plugin.synopsis | String | Brief description of the plugin or vulnerability. | 
| TenableIO.Vulnerability.plugin.type | String | The general type of plugin check \(for example, local or remote\). | 
| TenableIO.Vulnerability.plugin.unsupported_by_vendor | Boolean | Whether software found by this plugin is unsupported by the software's vendor \(for example, Windows 95 or Firefox 3\). | 
| TenableIO.Vulnerability.plugin.usn | String | Ubuntu security notice that the plugin covers. | 
| TenableIO.Vulnerability.plugin.version | String | The version of the plugin used to perform the check. | 
| TenableIO.Vulnerability.plugin.vuln_publication_date | Date | The publication date of the plugin. | 
| TenableIO.Vulnerability.plugin.xrefs.type | String | References to third-party information about the vulnerability, exploit, or update associated with the plugin. | 
| TenableIO.Vulnerability.plugin.xrefs.id | String | References to third-party information about the vulnerability, exploit, or update associated with the plugin. | 
| TenableIO.Vulnerability.plugin.vpr.score | Number | The Vulnerability Priority Rating \(VPR\) for the vulnerability. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.age_of_vuln | Number | A range representing the number of days since the National Vulnerability Database \(NVD\) published the vulnerability. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.age_of_vuln.lower_bound | Number | The lower bound of the range. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.age_of_vuln.upper_bound | Number | The upper bound of the range. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.exploit_code_maturity | String | The relative maturity of a possible exploit for the vulnerability based on the existence, sophistication, and prevalence of exploit intelligence from internal and external sources. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.cvss3_impact_score | Number | The NVD-provided CVSSv3 impact score for the vulnerability. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.cvss_impact_score_predicted | Boolean | A value specifying whether Tenable.io predicted the CVSSv3 impact score for the vulnerability. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.threat_intensity_last28 | String | The relative intensity based on the number and frequency of recently observed threat events related to this vulnerability: Very Low, Low, Medium, High, or Very High. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.threat_recency | String | A range representing the number of days since a threat event occurred for the vulnerability. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.threat_recency.lower_bound | String | The lower bound of the range. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.threat_recency.upper_bound | String | The upper bound of the range. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.threat_sources_last28 | String | A list of all sources \(for example, social media channels, the dark web, etc.\) where threat events related to this vulnerability occurred. | 
| TenableIO.Vulnerability.plugin.vpr.drivers.product_coverage | String | The relative number of unique products affected by the vulnerability: 'Low', 'Medium', 'High', or 'Very High'. | 
| TenableIO.Vulnerability.plugin.vpr.updated | Date | The ISO timestamp when Tenable.io last imported the VPR for this vulnerability. | 
| TenableIO.Vulnerability.port.port | Number | The port the scanner used to communicate with the asset. | 
| TenableIO.Vulnerability.port.protocol | String | The protocol the scanner used to communicate with the asset. | 
| TenableIO.Vulnerability.port.service | String | The service the scanner used to communicate with the asset. | 
| TenableIO.Vulnerability.recast_reason | String | The text that appears in the Comment field of the recast rule in the Tenable.io user interface. | 
| TenableIO.Vulnerability.recast_rule_uuid | String | The UUID of the recast rule that applies to the plugin. | 
| TenableIO.Vulnerability.scan.completed_at | Date | The ISO timestamp when the scan completed. | 
| TenableIO.Vulnerability.scan.schedule_uuid | String | The schedule UUID for the scan that found the vulnerability. | 
| TenableIO.Vulnerability.scan.started_at | Date | The ISO timestamp when the scan started. | 
| TenableIO.Vulnerability.scan.uuid | String | The UUID of the scan that found the vulnerability. | 
| TenableIO.Vulnerability.severity | String | The severity of the vulnerability as defined using the Common Vulnerability Scoring System \(CVSS\) base score. | 
| TenableIO.Vulnerability.severity_id | Number | The code for the severity assigned when a user recast the risk associated with the vulnerability. | 
| TenableIO.Vulnerability.severity_default_id | Number | The code for the severity originally assigned to a vulnerability before a user recast the risk associated with the vulnerability. | 
| TenableIO.Vulnerability.severity_modification_type | String | The type of modification a user made to the vulnerability's severity. | 
| TenableIO.Vulnerability.first_found | Date | The ISO date when a scan first detected the vulnerability on the asset. | 
| TenableIO.Vulnerability.last_fixed | Date | The ISO date when a scan no longer detects the previously detected vulnerability on the asset. | 
| TenableIO.Vulnerability.last_found | Date | The ISO date when a scan last detected the vulnerability on the asset. | 
| TenableIO.Vulnerability.state | String | The state of the vulnerability as determined by the Tenable.io state service. | 
| TenableIO.Vulnerability.indexed | Date | The date and time \(in Unix time\) when the vulnerability was indexed into Tenable.io. | 

#### Command example

```!tenable-io-export-vulnerabilities numAssets=500```

#### Context Example

```json
{
    "TenableIO": {
        "Vulnerability": [
            {
                "asset": {
                    "device_type": "general-purpose",
                    "fqdn": "fqdn",
                    "hostname": "1.1.1.1",
                    "ipv4": "1.1.1.1",
                    "last_unauthenticated_results": "2024-11-07T11:11:05.906Z",
                    "network_id": "00000000-0000-0000-0000-000000000000",
                    "operating_system": [
                        "Linux Kernel 3.13 on Ubuntu 14.04 (trusty)"
                    ],
                    "tracked": true,
                    "uuid": "fake_uuid"
                },
                "first_found": "2024-11-07T11:11:05.906Z",
                "indexed": "2024-11-07T11:11:05.906Z",
                "last_fixed": "2024-11-07T11:11:05.906Z", 
                "last_found": "2024-11-07T11:11:05.906Z",
                "output": "outputs",
                "plugin": {
                    "checks_for_default_account": false,
                    "checks_for_malware": false,
                    "cvss3_base_score": 0,
                    "cvss3_temporal_score": 0,
                    "cvss_base_score": 0,
                    "cvss_temporal_score": 0,
                    "description": "Description",
                    "exploit_available": false,
                    "exploit_framework_canvas": false,
                    "exploit_framework_core": false,
                    "exploit_framework_d2_elliot": false,
                    "exploit_framework_exploithub": false,
                    "exploit_framework_metasploit": false,
                    "exploited_by_malware": false,
                    "exploited_by_nessus": false,
                    "family": "General",
                    "family_id": 30,
                    "has_patch": false,
                    "id": 00000,
                    "in_the_news": false,
                    "modification_date": "2024-11-07T11:11:05Z",
                    "name": "Name",
                    "publication_date": "2024-11-07T11:11:05Z",
                    "risk_factor": "None",
                    "see_also": [
                        ""
                    ],
                    "solution": "N/A",
                    "synopsis": "synopsis",
                    "type": "remote",
                    "unsupported_by_vendor": false,
                    "version": "$Revision: 1.16 $"
                },
                "port": {
                    "port": 0,
                    "protocol": "TCP"
                },
                "scan": {
                    "completed_at": "2024-11-07T11:11:05.906Z",
                    "schedule_uuid": "fake_uuid",
                    "started_at": "2024-11-07T11:11:05.906Z",
                    "uuid": "fake_uuid"
                },
                "severity": "info",
                "severity_default_id": 0,
                "severity_id": 0,
                "severity_modification_type": "NONE",
                "state": "OPEN"
            },
            {
                "asset": {
                    "device_type": "general-purpose",
                    "fqdn": "fqdn",
                    "hostname": "1.3.2.1",
                    "ipv4": "1.3.2.1",
                    "last_unauthenticated_results": "2024-11-07T11:11:05Z",
                    "network_id": "00000000-0000-0000-0000-000000000000",
                    "operating_system": [
                        "Nutanix"
                    ],
                    "tracked": true,
                    "uuid": "fake_uuid"
                },
                "first_found": "2024-11-07T11:11:05.906Z",
                "indexed": "2024-11-07T11:11:05.906Z",
                "last_fixed": "2024-11-07T11:11:05.906Z",
                "last_found": "2024-11-07T11:11:05.906Z",
                "output": "outputs",
                "plugin": {
                    "checks_for_default_account": false,
                    "checks_for_malware": false,
                    "cvss3_base_score": 0,
                    "cvss3_temporal_score": 0,
                    "cvss_base_score": 0,
                    "cvss_temporal_score": 0,
                    "description": "Description",
                    "exploit_available": false,
                    "exploit_framework_canvas": false,
                    "exploit_framework_core": false,
                    "exploit_framework_d2_elliot": false,
                    "exploit_framework_exploithub": false,
                    "exploit_framework_metasploit": false,
                    "exploited_by_malware": false,
                    "exploited_by_nessus": false,
                    "family": "SMTP problems",
                    "family_id": 12,
                    "has_patch": false,
                    "id": 00000,
                    "in_the_news": false,
                    "modification_date": "2024-11-07T11:11:05Z",
                    "name": "Name",
                    "publication_date": "2024-11-07T11:11:05Z",
                    "risk_factor": "None",
                    "see_also": [],
                    "solution": "N/A",
                    "synopsis": "synopsis.",
                    "type": "remote",
                    "unsupported_by_vendor": false,
                    "version": "1.12"
                },
                "port": {
                    "port": 25,
                    "protocol": "TCP",
                    "service": "smtp"
                },
                "scan": {
                    "completed_at": "2024-11-07T11:11:05.906Z",
                    "schedule_uuid": "fake_uuid",
                    "started_at": "2024-11-07T11:11:05.906Z",
                    "uuid": "fake_uuid"
                },
                "severity": "info",
                "severity_default_id": 0,
                "severity_id": 0,
                "severity_modification_type": "NONE",
                "state": "OPEN"
            },
        ]
    }
}
```

#### Human Readable Output

>### Export Vulnerabilities Results:

>|ASSET ID|ASSET NAME|IPV4 ADDRESS|OPERATING SYSTEM|SYSTEM TYPE|DNS NAME (FQDN)|SEVERITY|PLUGIN ID|PLUGIN NAME|VULNERABILITY PRIORITY RATING|CVSSV2 BASE SCORECVE|PROTOCOL|PORT|FIRST SEEN|LAST SEEN|DESCRIPTION|SOLUTION|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| fake_uuid | 1.1.1.1 | 1.1.1.1 | Linux Kernel 3.13 on Ubuntu 14.04 (trusty) | general-purpose | fqdn | info | 00000 | Name |  |  | TCP | 22 | 2024-11-07T11:11:05.906Z | 2024-11-07T11:11:05.906Z | Description | N/A |
>| fake_uuid | 1.3.2.1 | 1.3.2.1 | Nutanix | general-purpose | fqdn | info | 00000 | Name |  |  | TCP | 0 | 2024-11-07T11:11:05.906Z | 2024-11-07T11:11:05.906Z | Description | N/A |
### tenable-io-list-scan-filters

***
Lists the filtering, sorting, and pagination capabilities available for scan records on endpoints/commands that support them.

#### Base Command

`tenable-io-list-scan-filters`

#### Input

---
There are no inputs for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.ScanFilter.name | String | The name of the scan filter. | 
| TenableIO.ScanFilter.readable_name | String | The readable name of the scan filter. | 
| TenableIO.ScanFilter.control.type | String | The type of control associated with the scan filter. | 
| TenableIO.ScanFilter.control.regex | String | The regular expression used by the scan filter. | 
| TenableIO.ScanFilter.control.readable_regex | String | An example expression that the filter's regular expression would match. | 
| TenableIO.ScanFilter.operators | String | The operators available for the scan filter. | 
| TenableIO.ScanFilter.group_name | String | The group name associated with the scan filter. | 

#### Command example
```!tenable-io-list-scan-filters```
#### Context Example
```json
{
    "TenableIO": {
        "ScanFilter": [
            {
                "control": {
                    "readable_regex": "01234567-abcd-ef01-2345-6789abcdef01",
                    "regex": "[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}(,[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12})*",
                    "type": "entry"
                },
                "group_name": null,
                "name": "host.id",
                "operators": [
                    "eq",
                    "neq",
                    "match",
                    "nmatch"
                ],
                "readable_name": "Asset ID"
            },
            {
                "control": {
                    "maxlength": 18,
                    "readable_regex": "NUMBER",
                    "regex": "^[0-9]+(,[0-9]+)*",
                    "type": "entry"
                },
                "group_name": null,
                "name": "plugin.attributes.bid",
                "operators": [
                    "eq",
                    "neq",
                    "match",
                    "nmatch"
                ],
                "readable_name": "Bugtraq ID"
            }
        ]
    }
}
```

#### Human Readable Output

>### Tenable IO Scan Filters
>|Filter name|Filter Readable name|Filter Control type|Filter regex|Readable regex|Filter operators|
>|---|---|---|---|---|---|
>| host.id | Asset ID | entry | [0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}(,[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12})* | 01234567-abcd-ef01-2345-6789abcdef01 | eq,<br/>neq,<br/>match,<br/>nmatch |
>| plugin.attributes.bid | Bugtraq ID | entry | ^[0-9]+(,[0-9]+)* | NUMBER | eq,<br/>neq,<br/>match,<br/>nmatch |

### tenable-io-get-scan-history

***
Lists the individual runs of the specified scan.

#### Base Command

`tenable-io-get-scan-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The ID of the scan of which to get the runs. | Required | 
| sortFields | A comma-separated list of fields by which to sort, in the order defined by "sortOrder". Possible values are: start_date, end_date, status. | Optional | 
| sortOrder | A comma-separated list of directions in which to sort the fields defined by "sortFields".<br/>If multiple directions are chosen, they will be sequentially matched with "sortFields".<br/>If only one direction is chosen it will be used to sort all values in "sortFields".<br/>For example:<br/>  If sortFields is "start_date,status" and sortOrder is "asc,desc",<br/>  then start_date is sorted in ascending order and status in descending order.<br/>  If sortFields is "start_date,status" and sortOrder is simply "asc",<br/>  then both start_date and status are sorted in ascending order.<br/>. Possible values are: asc, desc. Default is asc. | Optional | 
| excludeRollover | Whether to exclude rollover scans from the scan history. Possible values are: true, false. Default is false. | Optional | 
| page | The page number of scan records to retrieve (used for pagination) starting from 1. The page size is defined by the "pageSize" argument. | Optional | 
| pageSize | The number of scan records per page to retrieve (used for pagination). The page number is defined by the "page" argument. | Optional | 
| limit | The maximum number of records to retrieve. If "pageSize" is defined, this argument is ignored. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.ScanHistory.time_end | Number | The end time of the scan. | 
| TenableIO.ScanHistory.scan_uuid | String | The UUID (Universally Unique Identifier) of the scan. | 
| TenableIO.ScanHistory.id | Number | The ID of the scan history. | 
| TenableIO.ScanHistory.is_archived | Boolean | Indicates whether the scan is archived or not. | 
| TenableIO.ScanHistory.time_start | Number | The start time of the scan. | 
| TenableIO.ScanHistory.visibility | String | The visibility of the scan. | 
| TenableIO.ScanHistory.targets.custom | Boolean | Indicates whether custom targets were used in the scan. | 
| TenableIO.ScanHistory.targets.default | Boolean | Indicates whether the default targets were used in the scan. | 
| TenableIO.ScanHistory.status | String | The status of the scan. | 

#### Command example
```!tenable-io-get-scan-history scanId=16 excludeRollover=true sortFields=end_date,status sortOrder=desc page=2 pageSize=4```
#### Context Example
```json
{
    "TenableIO": {
        "ScanHistory": [
            {
                "id": 17235445,
                "is_archived": true,
                "reindexing": null,
                "scan_uuid": "69a55b8e-0d52-427a-81e0-7dfe4dc6eda6",
                "status": "completed",
                "targets": {
                    "custom": null,
                    "default": false
                },
                "time_end": 1677425182,
                "time_start": 1677424566,
                "visibility": "public"
            },
            {
                "id": 17235342,
                "is_archived": true,
                "reindexing": null,
                "scan_uuid": "2c592d52-df56-42e0-9f18-d892bdeb1e18",
                "status": "completed",
                "targets": {
                    "custom": null,
                    "default": false
                },
                "time_end": 1677424556,
                "time_start": 1677423906,
                "visibility": "public"
            },
            {
                "id": 17235033,
                "is_archived": true,
                "reindexing": null,
                "scan_uuid": "44586b4f-1051-415c-b375-db86f6bd8c13",
                "status": "completed",
                "targets": {
                    "custom": null,
                    "default": false
                },
                "time_end": 1677423865,
                "time_start": 1677423247,
                "visibility": "public"
            },
            {
                "id": 17234969,
                "is_archived": true,
                "reindexing": null,
                "scan_uuid": "06c12bf7-436f-489d-bb04-aae511ea9f5c",
                "status": "completed",
                "targets": {
                    "custom": null,
                    "default": false
                },
                "time_end": 1677423205,
                "time_start": 1677422585,
                "visibility": "public"
            }
        ]
    }
}
```

#### Human Readable Output

>### Tenable IO Scan History
>|History id|History uuid|Status|Is archived|Targets default|Visibility|Time start|Time end|
>|---|---|---|---|---|---|---|---|
>| 17235445 | 69a55b8e-0d52-427a-81e0-7dfe4dc6eda6 | completed | true | false | public | 1677424566 | 1677425182 |
>| 17235342 | 2c592d52-df56-42e0-9f18-d892bdeb1e18 | completed | true | false | public | 1677423906 | 1677424556 |
>| 17235033 | 44586b4f-1051-415c-b375-db86f6bd8c13 | completed | true | false | public | 1677423247 | 1677423865 |
>| 17234969 | 06c12bf7-436f-489d-bb04-aae511ea9f5c | completed | true | false | public | 1677422585 | 1677423205 |

### tenable-io-export-scan

***
Export and download a scan report.
Scan results older than 35 days are supported in Nessus and CSV formats only, and filters cannot be applied.
Scans that are actively running cannot be exported (run "tenable-io-list-scans" to view scan statuses)


#### Base Command

`tenable-io-export-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanId | The identifier for the scan to export. Run the "tenable-io-list-scans" command to get all available scans. | Required | 
| historyId | The unique identifier of the historical data to export. Run the "tenable-io-get-scan-history" command to get history IDs. | Optional | 
| historyUuid | The UUID of the historical data to export. Run the "tenable-io-get-scan-history" command to get history UUIDs. | Optional | 
| format | The file format to export the scan in. Scans can be export in the HTML and PDF formats for up to 35 days.<br/> For scans that are older than 35 days, only the Nessus and CSV formats are supported.<br/> The "chapters" argument must be defined if the chosen format is HTML or PDF.<br/>. Possible values are: Nessus, HTML, PDF, CSV. Default is CSV. | Required | 
| chapters | A comma-separated list of chapters to include in the export. This argument is required if the file format is PDF or HTML. Possible values are: vuln_hosts_summary, vuln_by_host, compliance_exec, remediations, vuln_by_plugin, compliance. | Optional | 
| filter | A comma-separated list of filters, in the format of "name quality value" to apply to the exported scan report.<br/> Example: "port.protocol eq tcp, plugin_id eq 1234567"<br/> Note: when used literally, commas and spaces should be escaped. (i.e. "\\\\," for comma and "\\\\s" for space)<br/> Filters cannot be applied to scans older than 35 days.<br/> Run "tenable-io-list-scan-filters" to get all available filters, ("Filter name" (name), "Filter operators" (quality) and "Readable regex" (value) in response).<br/> For more information: https://developer.tenable.com/docs/scan-export-filters-tio<br/>. | Optional | 
| filterSearchType | For multiple filters, specifies whether to use the AND or the OR logical operator. Possible values are: AND, OR. Default is AND. | Optional | 
| assetId | The ID of the asset scanned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Size | number | The size of the file in bytes. | 
| InfoFile.Name | string | The name of the file. | 
| InfoFile.EntryID | string | The War Room entry ID of the file. | 
| InfoFile.Info | string | The format and encoding of the file. | 
| InfoFile.Type | string | The type of the file. | 
| InfoFile.Extension | unknown | The file extension of the file. | 

#### Command example
```!tenable-io-export-scan scanId=16 format=HTML chapters="compliance_exec,remediations,vuln_by_plugin" historyId=19540157 historyUuid=f7eaad37-23bd-4aac-a979-baab0e9a465b filterSearchType=OR filter="port.protocol eq tcp, plugin_id eq 1234567" assetId=10```
#### Human Readable Output

>Preparing scan report:

>Returned file: scan_16_SSE-144f3dc6-cb2d-42fc-b6cc-dd20b807735f-html.html [Download](https://www.paloaltonetworks.com/cortex)

### tenable-io-get-audit-logs
***
Returns audit logs extracted from Tenable io.


#### Base Command

`tenable-io-get-audit-logs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True in order to create events, otherwise the command will only display the events. Possible values are: true, false. Default is false. | Required | 
| limit | The maximum number of alerts to return (maximum value - 5000). | Optional | 
| from_date | Return events that occurred after the specified date.  | Optional | 
| to_date | Return events that occurred before the specified date. | Optional | 
| actor_id | Return events that contain the specified actor UUID. | Optional | 
| target_id | Return events matching the specified target UUID. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example
```!tenable-io-get-audit-logs limit=1```


#### Human Readable Output

>### Audit Logs List:
>|Action| Actor    | Crud | Description | Fields                                                                                                                                                  | Id  |Is Anonymous|Is Failure|Received| Target                                              |
>|----------|------|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|-----|---|---|---|-----------------------------------------------------|---|
>| user.create | id: test | c    |             | {'key': 'X-Access-Type', 'value': 'apikey'},<br>{'key': 'X-Forwarded-For', 'value': '1.2.3.4'},<br>{'key': 'X-Request-Uuid', 'value': '12:12:12:12:12'} | 12  | true | false | 2022-05-18T16:33:02Z | id: 12-1-1-1-1<br>name: test@test.com<br>type: User |


### tenable-io-list-templates

***
Lists Tenable-provided scan templates. 

#### Base Command

`tenable-io-list-templates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of templates to retrieve (scan, policy, or remediation). Possible values are: scan, policy, remediation. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Templates.unsuported | boolean | If true, the template is not supported. | 
| TenableIO.Templates.cloud_only | boolean | If true, the template is only available on the cloud. | 
| TenableIO.Templates.desc | string | The description of the template. | 
| TenableIO.Templates.subscription_only | boolean | If true, the template is only available for subscribers. | 
| TenableIO.Templates.is_was | boolean | If true, the template can be used for Tenable Web App Scanning only. | 
| TenableIO.Templates.title | string | The long name of the template. | 
| TenableIO.Templates.is_agent | boolean | If true, the template can only be used for agent scans. | 
| TenableIO.Templates.uuid | string | The UUID for the template. Use this value to specify the template when creating scans and policies. | 
| TenableIO.Templates.manager_only | boolean | If true, can only be used by manager. | 
| TenableIO.Templates.name | string | The short name of the template. | 

### tenable-io-get-plugin-details

***
Gets the details of the plugin associated with the scan or policy.

#### Base Command

`tenable-io-get-plugin-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| plugin_id | The ID of the plugin to lookup within the family. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.PluginDetails.risk_factor | string | The severity level of the vulnerabilities targeted by the plugin. | 
| TenableIO.PluginDetails.plugin_name | string | The name of the plugin. | 
| TenableIO.PluginDetails.plugin_publication_date | date | The date the plugin was published. | 
| TenableIO.PluginDetails.family_name | string | The name of the plugin family. | 
| TenableIO.PluginDetails.id | number | The ID of the plugin. | 
| TenableIO.PluginDetails.synopsis | string | A brief summary of the vulnerability. | 
| TenableIO.PluginDetails.description | string | The description of the vulnerability. | 
| TenableIO.PluginDetails.solution | string | Information on how to fix the vulnerability. | 
| TenableIO.PluginDetails.script_version | string | The plugin version. | 
| TenableIO.PluginDetails.fname | string | Name of impacted file. | 
| TenableIO.PluginDetails.name | string | The name of the plugin. | 

### tenable-io-list-policies

***
Returns a list of policies (scan templates).

#### Base Command

`tenable-io-list-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Policies.id | number | The unique ID of the policy. | 
| TenableIO.Policies.template_uuid | string | The UUID for the Tenable-provided template used to create the policy. | 
| TenableIO.Policies.name | string | The name of the policy. | 
| TenableIO.Policies.description | string | The description of the policy. | 
| TenableIO.Policies.owner_id | string | The unique ID of the owner of the policy. | 
| TenableIO.Policies.owner | string | The username for the owner of the policy. | 
| TenableIO.Policies.shared | number | The shared status of the policy \(1 if shared with users other than owner, 0 if not shared\). | 
| TenableIO.Policies.user_permissions | number | The sharing permissions for the policy. | 
| TenableIO.Policies.creation_date | number | The creation date of the policy in Unix time format. | 
| TenableIO.Policies.last_modification_date | number | The last modification date for the policy in Unix time format. | 
| TenableIO.Policies.visibility | number | The visibility of the target \(private or shared\). | 
| TenableIO.Policies.no_target | boolean | If true, the policy configuration does not include targets. | 

### tenable-io-list-folders

***
Lists both Tenable-provided folders and the current user's custom folders.

#### Base Command

`tenable-io-list-folders`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Folders.id | number | The unique ID of the folder. | 
| TenableIO.Folders.name | string | The name of the folder. This value corresponds to the folder type as follows:  main—My Scans trash—Trash -custom—user-defined string. | 
| TenableIO.Folders.type | string | The type of the folder:  main—Tenable-provided folder. Contains all scans that you create but do not assign to a custom folder, as well as any scans shared with you by other users. If you do not specify a scan folder when creating a scan, Tenable Vulnerability Management stores scans in this folder by default. This folder corresponds to the My Scans folder in the Tenable Vulnerability Management user interface. trash—Tenable-provided folder. This folder corresponds to the Trash folder in the Tenable Vulnerability Management user interface. It contains all scans that the current user has moved to the trash folder. After you move a scan to the trash folder, the scan remains in the trash folder until a user with at least Can Edit \[64\] scan permissions permanently deletes the scan. custom—User-created folder. Contains scans as assigned by the current user. You can create custom folders to meet your organizational needs. | 
| TenableIO.Folders.default_tag | number | Indicates whether or not the folder is the default:  1—The folder is the default. 0—The folder is not the default. The main folder is the default folder. You cannot change the default folder. | 
| TenableIO.Folders.custom | number | Indicates whether or not the folder is a custom folder:  1—User-created folder. You can rename or delete this folder. 0—System-created folder. You cannot rename or delete this folder. | 
| TenableIO.Folders.unread_count | number | The number of scans in the folder that the current user has not yet viewed in the Tenable Vulnerability Management user interface. | 

### tenable-io-list-plugins-by-family

***
Returns the list of plugins for the specified family ID.

#### Base Command

`tenable-io-list-plugins-by-family`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the plugin family you want to retrieve the list of plugins for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Family.plugins.id | number | The unique ID of the plugin. | 
| TenableIO.Family.plugins.name | string | The name of the plugin. | 
| TenableIO.Family.id | number | The name of the plugin family. | 
| TenableIO.Family.name | string | The unique ID of the plugin family. | 

### tenable-io-list-plugin-families

***
Returns the list of plugin families.

#### Base Command

`tenable-io-list-plugin-families`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| all | Specifies whether to return all plugin families. If true, the plugin families hidden in Tenable Vulnerability Management UI, for example, Port Scanners, are included in the list. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Families.count | number | The number of plugins in the family. | 
| TenableIO.Families.name | string | The name of the family. | 
| TenableIO.Families.id | number | The unique ID of the family. | 

### tenable-io-list-scanners

***
Returns the scanner list.

#### Base Command

`tenable-io-list-scanners`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scanners.creation_date | number | The Unix timestamp when the scanner was created. This attribute specifies the original creation date if the scanner was migrated. | 
| TenableIO.Scanners.distro | string | The scanner operating system distribution. | 
| TenableIO.Scanners.group | boolean | Indicates whether the scanner belongs to a scanner group \('true'\) or not \('false'\). | 
| TenableIO.Scanners.hostname | string | The hostname of the scanner. | 
| TenableIO.Scanners.id | number | The unique ID of the scanner. | 
| TenableIO.Scanners.ip_addresses | string | A list of IP addresses associated with the scanner. | 
| TenableIO.Scanners.key | string | The linking key, that is, the alpha-numeric sequence of characters you use to link a scanner to Tenable Vulnerability Management. For more information about linking a scanner, see the Link a Sensor in the Tenable Vulnerability Management User Guide. | 
| TenableIO.Scanners.last_connect | string | The Unix timestamp when any of the scanner's tasks have provided its last update. | 
| TenableIO.Scanners.last_modification_date | number | The Unix timestamp when the scanner was last modified. | 
| TenableIO.Scanners.engine_version | string | The version of the scanner. | 
| TenableIO.Scanners.loaded_plugin_set | string | The current plugin set on the scanner. | 
| TenableIO.Scanners.registration_code | string | The registration code of the scanner. | 
| TenableIO.Scanners.license.type | string | The license type. | 
| TenableIO.Scanners.license.ips | number | The number of hosts the scanner is licensed to use. | 
| TenableIO.Scanners.license.agents | number | The number of agents the scanner is licensed to use. | 
| TenableIO.Scanners.license.scanners | unknown | The number of scanners the scanner is licensed to use. | 
| TenableIO.Scanners.license.apps.type | string | The Tenable products licensed on the scanner. | 
| TenableIO.Scanners.license.apps.consec.type | string | Indicates that the scanner is licensed to perform Tenable Container Security scans. | 
| TenableIO.Scanners.license.apps.consec.mode | number | Indicates whether the product license is an evaluation license \(eval\) or standard license \(standard\). | 
| TenableIO.Scanners.license.apps.consec.expiration_date | number | The Unix timestamp when the license expires. | 
| TenableIO.Scanners.license.apps.consec.activation_code | number | The activation code you used to enable the license. This value is present for standard licenses only. | 
| TenableIO.Scanners.license.apps.consec.max_gb | number | The maximum memory \(in GB\) on the scanner allotted for the Tenable licensed application. | 
| TenableIO.Scanners.license.apps.was.type | string | Indicates that the scanner is licensed to perform Tenable Web App Scanning scans. | 
| TenableIO.Scanners.license.apps.was.mode | string | Indicates whether the product license is an evaluation license \(eval\) or standard license \(standard\). | 
| TenableIO.Scanners.license.apps.was.expiration_date | number | The Unix timestamp when the license expires. | 
| TenableIO.Scanners.license.apps.was.activation_code | number | The activation code you used to enable the license. This value is present for standard licenses only. | 
| TenableIO.Scanners.license.apps.was. web_assets | number | The number of web assets which your license authorizes you to scan. | 
| TenableIO.Scanners.linked | number | Specifies whether you disabled \(0\) or enabled \(1\) the scanner.  | 
| TenableIO.Scanners.name | string | The user-defined name of the scanner. | 
| TenableIO.Scanners.network_name | string | The name of the network object associated with the scanner. | 
| TenableIO.Scanners.num_scans | number | The number of scans \(tasks\) the scanner is currently executing. | 
| TenableIO.Scanners.owner | string | The owner of the scanner. | 
| TenableIO.Scanners.owner_id | number | The ID of the owner of the scanner. | 
| TenableIO.Scanners.owner_name | string | The username of the owner of the scanner. | 
| TenableIO.Scanners.owner_uuid | string | The UUID of the owner of the scanner. | 
| TenableIO.Scanners.platform | string | The platform of the scanner. | 
| TenableIO.Scanners.pool | boolean | Indicates whether the scanner is part of a scanner group \('true'\) or not \('false'\). | 
| TenableIO.Scanners.scan_count | number | The number of scans that the scanner is currently running. | 
| TenableIO.Scanners.shared | boolean | Indicates whether anyone other than the scanner owner has explicit access to the scanner \(1\). | 
| TenableIO.Scanners.source | string | Always set to service. | 
| TenableIO.Scanners.status | string | The status of the scanner \(on or off\). | 
| TenableIO.Scanners.timestamp | number | Equivalent to the last_modification_date attribute. | 
| TenableIO.Scanners.type | string | The type of scanner \(local, managed, managed_pvs, pool, remote, or webapp\). | 
| TenableIO.Scanners.ui_build | number | The backend build of Nessus that is running on the scanner. | 
| TenableIO.Scanners.ui_version | string | The backend version of Nessus that is running on the scanner. | 
| TenableIO.Scanners.user_permissions | number | The permissions you \(the current user\) have been assigned for the scanner.  | 
| TenableIO.Scanners.uuid | string | The UUID of the scanner. | 
| TenableIO.Scanners.remote_uuid | string | The UUID of the Nessus installation on the scanner. | 
| TenableIO.Scanners.supports_remote_logs | boolean | Indicates if the scanner supports remote logging. | 
| TenableIO.Scanners.supports_webapp | boolean | Indicates if the scanner supports Tenable Web App Scanning. | 
| TenableIO.Scanners.aws_update_interval | number | Specifies how often, in minutes, the scanner checks in with Tenable Vulnerability Management \(Amazon Web Services scanners only\). | 

### tenable-io-create-scan

***
Creates a scan configuration.

#### Base Command

`tenable-io-create-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_uuid | The UUID for the Tenable-provided scan template to use. | Required | 
| credentials | An object that specifies credential parameters that enable a scanner to authenticate a connection to a target host.  See https://developer.tenable.com/reference/scans-create for example json. | Optional | 
| plugins | A list of plugins to add to the non-remediation scans.  See https://developer.tenable.com/reference/scans-create for examples. | Optional | 
| settings | JSON object containing settings for scan.  Must include name at a minimum.  See https://developer.tenable.com/reference/scans-create for example and other config options. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Scan.tag_type | string | The type of tag. | 
| TenableIO.Scan.container_id | string | The unique ID of your Tenable Vulnerability Management instance. | 
| TenableIO.Scan.owner_uuid | string | The unique ID of the scan owner. | 
| TenableIO.Scan.uuid | string | The UUID of the schedule for the scan. | 
| TenableIO.Scan.name | string | The user-defined scan name. | 
| TenableIO.Scan.description | string | A brief user-defined description of the scan. | 
| TenableIO.Scan.policy_id | number | The unique ID of the policy associated with the scan. | 
| TenableIO.Scan.scanner_uuid | string | The UUID of the scanner that the scan is configured to use, if the scan is not configured for scan routing. | 
| TenableIO.Scan.target_network_uuid | string | The UUID of the network object that Tenable Vulnerability Management associates with the scan results if the scan is configured for scan routing. | 
| TenableIO.Scan.emails | string | A comma-separated list of accounts that receive the email summary report. | 
| TenableIO.Scan.sms | string | A comma-separated list of mobile phone numbers that receive notification of the scan. | 
| TenableIO.Scan.enabled | boolean | A value indicating whether the scan schedule is active \(true\) or inactive \(false\). | 
| TenableIO.Scan.dashboard_file | string | The name of the dashboard file associated with the scan. | 
| TenableIO.Scan.remediation | number | If 1, your vulnerability remediation actions on scan targets have been successful. | 
| TenableIO.Scan.include_aggregate | boolean | A value indicating whether the scan results appear in dashboards. | 
| TenableIO.Scan.scan_time_window | string | Depends on the type of scan:  For Nessus Agent scans, scan_time_window is the time frame, in minutes, during which agents must transmit scan results to Tenable Vulnerability Management in order to be included in dashboards and reports. If your request omits this parameter, the default value is 180 minutes. For Nessus scanner scans, scan_time_window is the time frame, in minutes, after which the scan will automatically stop. If your request omits this parameter, the default value is 0 and the scan will not stop after a certain time frame. | 
| TenableIO.Scan.custom_targets | string | Targets specified in the alt_targets parameter of the POST /scans/\{scan_id\}/launch request body used to run the scan. | 
| TenableIO.Scan.triggers.type | string | The type of scan launch trigger \(periodic or file-exists\). | 
| TenableIO.Scan.triggers.options. periodic_hourly_interval | number | The number of hours between successive scan launches. This option is only applicable for scan trigger type periodic. | 
| TenableIO.Scan.triggers.options. filename | string | The name of the file which, when created, will trigger a scan launch. This option is only applicable for scan trigger type file-exists. | 
| TenableIO.Scan.reporting_mode | string | Indicates the reporting mode for Nessus Agent scans:  baseline—A scan that always reports all detected findings regardless of severity level. For baseline scans, the Nessus Agent creates a local cache of the plugin outputs generated by the scan. The cache is then used as the base for differential comparisons in subsequent scans. differential—A scan that produces smaller results by removing plugin outputs that have not changed since the last scan. null—A normal Nessus Agent scan that does not support baseline or differential reporting modes. | 
| TenableIO.Scan.interval_type | string | For Nessus Agent scans, indicates whether the info-level reporting setting \(refresh_reporting_type\) is set to scans or days. | 
| TenableIO.Scan.interval_value | number | For Nessus Agent scans, indicates the interval value for info-level reporting. For the scans refresh reporting interval type, values range from 2 to 10. For the days refresh reporting interval type, values range from 1 to 7. | 
| TenableIO.Scan.baseline_next_scan | string | Indicates whether or not the next Nessus Agent scan is a baseline scan. A baseline scan is a Nessus Agent scan that always reports all detected findings regardless of severity level. For baseline scans, the Nessus Agent creates a local cache of the plugin outputs generated by the scan. The cache is then used as the base for differential comparisons in subsequent scans. | 
| TenableIO.Scan.agent_scan_launch_type | string | For Nessus Agent scans, indicates whether the agent scan should use the scan window \(scheduled\) or rule-based \(triggered\) method for scan launches. | 
| TenableIO.Scan.starttime | string | For one-time scans, the starting time and date for the scan. For recurrent scans, the first date on which the scan schedule is active and the time that recurring scans launch based on the rrules parameter.  This attribute has the following format: YYYYMMDDTHHMMSS. | 
| TenableIO.Scan.rrules | string | The interval at which the scan repeats. The interval is formatted as a string of three values delimited by semi-colons. These values are: the frequency \(FREQ=ONETIME or DAILY or WEEKLY or MONTHLY or YEARLY\), the interval \(INTERVAL=1 or 2 or 3 ... x\), and the days of the week \(BYDAY=SU,MO,TU,WE,TH,FR,SA\). For a scan that runs every three weeks on Monday Wednesday and Friday, the string would be FREQ=WEEKLY;INTERVAL=3;BYDAY=MO,WE,FR. If the scan is not scheduled to recur, this attribute is null.  | 
| TenableIO.Scan.timezone | string | The timezone of the scheduled start time for the scan. | 
| TenableIO.Scan.notification_filters.value | string | The attribute value Tenable Vulnerability Management filters on. For example, when filtering on severity, this attribute might specify Critical. | 
| TenableIO.Scan.notification_filters.quality | string | The operator Tenable Vulnerability Management applies to the filter value, for example, eq. | 
| TenableIO.Scan.notification_filters.filter | string | The attribute name. For example, use the risk_factor attribute if you want to filter on vulnerability severity. | 
| TenableIO.Scan.tag_targets | string | The list of asset tag identifiers the scan uses to determine which assets it evaluates. | 
| TenableIO.Scan.shared | boolean | If 1, the scan is shared with users other than the scan owner. The level of sharing is specified in the acls attribute of the scan details. | 
| TenableIO.Scan.user_permissions | number | The sharing permissions for the scan. | 
| TenableIO.Scan.default_permissions | string | The default permissions for the scan. | 
| TenableIO.Scan.owner | string | The owner of the scan. | 
| TenableIO.Scan.owner_id | number | The unique ID of the owner of the scan. | 
| TenableIO.Scan.last_modification_date | date | For newly-created scans, the date on which the scan configuration was created. For scans that have been launched at least once, this attribute does not represent the date on which the scan configuration was last modified. Instead, it represents the date on which the scan was last launched, in Unix time format. Tenable Vulnerability Management updates this attribute each time the scan launches. | 
| TenableIO.Scan.creation_date | date | For newly-created scans, the date on which the scan configuration was originally created. For scans that have been launched at least once, this attribute does not represent the date on which the scan configuration was originally created. Instead, it represents the date on which the scan was first launched, in Unix time format. | 
| TenableIO.Scan.type | string | The type of scan. | 
| TenableIO.Scan.id | number | The unique ID of the scan. | 

### tenable-io-list-connectors

***
Returns a list of connectors.

#### Base Command

`tenable-io-list-connectors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of records to retrieve. If this parameter is omitted, Tenable Vulnerability Management uses the default value of 1000. Default is 1000. | Optional | 
| offset | The starting record to retrieve. If this parameter is omitted, Tenable Vulnerability Management uses the default value of 0. Default is 0. | Optional | 
| sort | The field you want to use to sort the results by along with the sort order. The field is specified first, followed by a colon, and the order is specified second (asc or desc). For example, name:desc would sort results by the name field in descending order.  If you specify multiple fields, the fields must be separated by commas. For example, name:desc,date_created:asc would first sort results by the name field in descending order and then by the date_created field in ascending order. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Connectors.type | string | The type of the connector. Types include aws, aws_keyless, aws_fa, azure, azure_fa, or gcp. | 
| TenableIO.Connectors.human_type | string | The human-readable connector type. | 
| TenableIO.Connectors.data_type | string | The data type imported by the connector. This value is always assets. | 
| TenableIO.Connectors.name | string | The name of the connector. The name must be unique within a Tenable Vulnerability Management instance. | 
| TenableIO.Connectors.status | string | The import status of the connector. Status values can include:  Completed—Tenable Vulnerability Management successfully used the connector to import assets \(no imports scheduled\) Scheduled—Imports using the connector are scheduled for future dates Saved—Tenable Vulnerability Management saved the connector configuration, but did not import assets at this time \(no imports scheduled\) Error—Tenable Vulnerability Management failed to import assets using the connector. | 
| TenableIO.Connectors.is_fa | boolean | For AWS keyless connectors, indicates whether Frictionless Assessment is enabled or not. | 
| TenableIO.Connectors.status_message | string | Extended description of the connector status. If Frictionless Assessment is enabled, this property is set to FA Enabled.  | 
| TenableIO.Connectors.schedule.units | string | The units of time for the import interval. Units can include days, hours, minutes. | 
| TenableIO.Connectors.schedule.value | number | The number of units between import intervals. | 
| TenableIO.Connectors.date_created | string | An ISO timestamp indicating the date and time on which the connector was created, for example, 2018-12-31T13:51:17.243Z. | 
| TenableIO.Connectors.date_modified | string | An ISO timestamp indicating the date and time on which the connector was last modified or new records were imported, for example, 2018-12-31T13:51:17.243Z. | 
| TenableIO.Connectors.id | string | The UUID of the connector. | 
| TenableIO.Connectors.container_uuid | string | The UUID of the Tenable Vulnerability Management instance. | 
| TenableIO.Connectors.expired | boolean | Indicates whether the Vulnerability Management license for the Tenable Vulnerability Management instance associated with the connector is expired. | 
| TenableIO.Connectors.incremental_mode | boolean | Indicates whether a connector has completed the initial full import successfully. If the value is true, then the connector is in incremental mode where it imports assets based on on the service provider event stream instead of enumerating all assets in the account every single time. | 
| TenableIO.Connectors.params.access_key | string | For AWS connectors, the AWS access key. | 
| TenableIO.Connectors.params.sub_accounts.account_id | string | The AWS account ID. | 
| TenableIO.Connectors.params.sub_accounts.role_arn | string | The Amazon Resource Name \(ARN\) of the role generated based on the associated account ID. | 
| TenableIO.Connectors.params.sub_accounts.external_id | string | The UUID of your Tenable Vulnerability Management instance used by AWS to identify it as a client application.  | 
| TenableIO.Connectors.params.sub_accounts.trails.arn | string | The Amazon Resource Name \(ARN\) of the cloudtrail. | 
| TenableIO.Connectors.params.sub_accounts.trails.name | string | The name of the cloudtrail. | 
| TenableIO.Connectors.params.sub_accounts.trails.region.name | string | The AWS region code, for example, us-east-1. The value of All indicates that the cloudtrail is associated with all AWS available regions. | 
| TenableIO.Connectors.params.sub_accounts.trails.region.friendly_name | string | The AWS region name, for example, US East \(N. Virginia\). The value of All indicates that the cloudtrail is associated with all AWS available regions. | 
| TenableIO.Connectors.params.sub_accounts.trails.availability | string | Indicates whether a cloudtrail is available to be used by a connector \(logging is turned on in AWS, or it has at least one EventSelector with IncludeManagementEvents\). Values include:  success—The cloudtrail is available. error—The cloudtrail is not available. | 
| TenableIO.Connectors.params.sub_accounts.incremental_mode | boolean | Indicates whether a connector has completed the initial full import successfully. If the value is true, then the connector is in incremental mode where it imports assets based on events instead of enumerating all assets in the account every single time. | 
| TenableIO.Connectors.params.status.last_event_seen | string | An ISO timestamp indicating the last time the connector found new or changed records and successfully imported them. | 
| TenableIO.Connectors.params.status.release_timestamp | string | An ISO timestamp indicating the last time the connector successfully completed an import \(regardless of whether it found any changes\). | 
| TenableIO.Connectors.params.status.message | string | The extended import status message. | 
| TenableIO.Connectors.params.targets.resource_group | string | The name of the resource group that Azure Frictionless Assessment scans VMs in. | 
| TenableIO.Connectors.params.targets.tag_key | string | The tag name in Microsoft Azure. | 
| TenableIO.Connectors.params.targets.tag_value | string | The tag value in Microsoft Azure. | 
| TenableIO.Connectors.params.application_id | string | For Azure connectors, the Azure application ID. | 
| TenableIO.Connectors.params.tenant_id | string | For Azure connectors, the Azure tenant ID \(directory ID\). | 
| TenableIO.Connectors.params.subscription_id | string | For Azure connectors, the Azure subscription ID. If you do not provide subscription IDs, Tenable Vulnerability Management automatically discovers them. | 
| TenableIO.Connectors.params.auto_discovery | boolean | Specifies whether Auto Discovery is enabled or not for AWS keyless connectors. If Auto Discovery is enabled, the connector will automatically discover linked accounts and CloudTrails. | 
| TenableIO.Connectors.params.service | string | The service targeted by the connector. Values include aws, aws_keyless, aws_fa, azure, azure_fa, and gcp. | 
| TenableIO.Connectors.last_sync_time | string | An ISO timestamp indicating the date and time of the last successful import, for example, 2018-12-31T13:51:17.243Z. | 
| TenableIO.Connectors.network_uuid | string | The UUID of the network associated with the connector. | 

### tenable-io-list-users

***
Returns a list of users.

#### Base Command

`tenable-io-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Users.uuid | string | The UUID of the user. | 
| TenableIO.Users.id | string | The unique ID of the user. | 
| TenableIO.Users.user_name | string | The username for the user. | 
| TenableIO.Users.username | string | The username for the user. | 
| TenableIO.Users.email | string | The email address of the user. If this attribute is empty, Tenable Vulnerability Management uses the username value as the user's email address. | 
| TenableIO.Users.name | string | The name of the user \(for example, first and last name\). | 
| TenableIO.Users.type | string | The type of user. The only supported type is local. | 
| TenableIO.Users.permissions | number | The user permissions. | 
| TenableIO.Users.last_login_attempt | number | The time \(in Unix milliseconds\) of the last time the user failed to log in to the Tenable Vulnerability Management user interface. This attribute is only present if the user has attempted unsuccessfully to log in to the Tenable Vulnerability Management user interface. | 
| TenableIO.Users.login_fail_count | number | The number of failed login attempts since the user last successfully logged in to the Tenable Vulnerability Management user interface.  If this attribute is greater than 5, Tenable Vulnerability Management locks the user account \(that is, updates the lockout attribute for the user to 1.\) | 
| TenableIO.Users.login_fail_total | number | The total number of failed login attempts for the user. | 
| TenableIO.Users.enabled | boolean | Specifies whether the user account is enabled \(true\) or disabled \(false\). | 
| TenableIO.Users.undeletable | boolean | Specifies whether the user account is undeletable \(true\) or deletable \(false\). | 
| TenableIO.Users.two_factor.sms_phone | string | The phone number used for two-factor authentication. The phone number begins with the \+ character and the country code. This field is required when sms_enabled is set to true. | 
| TenableIO.Users.two_factor.sms_enabled | number | Indicates whether two-factor authentication is enabled \(1\) or disabled \(0\). | 
| TenableIO.Users.two_factor.email_enabled | number | Indicates whether backup notification for two-factor authentication is enabled \(1\) or disabled \(0\). If enabled, Tenable Vulnerability Management sends the two-factor verification code via e-mail, as well as via the default SMS message. | 
| TenableIO.Users.lockout | number | Specifies whether the user can log into the Tenable Vulnerability Management user interface \(0\) or is locked out \(1\). | 
| TenableIO.Users.container_uuid | string | The UUID of the Tenable Vulnerability Management instance to which the user belongs. | 
| TenableIO.Users.lastlogin | number | The last time \(in Unix milliseconds\) that the user successfully logged in to the Tenable Vulnerability Management user interface. This attribute is only present if the user has logged in at least once successfully to the Tenable Vulnerability Management user interface. | 
| TenableIO.Users.uuid_id | string | The UUID for the user. | 

### tenable-io-delete-user

***
Deletes a user.

#### Base Command

`tenable-io-delete-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The UUID (uuid) or unique ID (id) of the user. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TenableIO.Delete.User | unknown | User ID that was sent for removal. | 
| TenableIO.Delete.Removed | unknown | Boolean to identify if the removal was successful. | 
