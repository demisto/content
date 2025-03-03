Prisma Cloud secures infrastructure, workloads and applications, across the entire cloud-native technology stack.
This integration was integrated and tested with version 23.2.1 of PrismaCloud

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration---prisma-cloud-v2).

## Configure Prisma Cloud v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Username / Access Key ID |  | True |
| Password / Access Key Secret |  | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Incident type |  | False |
| Maximum number of incidents to fetch | Maximum is limited to 200. | False |
| First fetch time interval | Date or relative timestamp to start fetching incidents from, in the format of &amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;. For example, 2 minutes, 12 hours, 6 days, 2 weeks, 3 months, 1 year, ISO timestamp. Default is 3 days. | False |
| Advanced: Time in minutes to look back when fetching incidents | Use this parameter to determine how far back to look in the search for incidents that were created before the last run time and did not match the query when they were created. When choosing to increase this value, duplicate incidents might occur at increase time. | False |
| Fetch only incidents matching these filters | Comma-separated list of filter name and value, in the following format: filtername1=filtervalue1,filtername2=filtervalue2,etc. Names and possible values for filters can be found by running the "prisma-cloud-alert-filter-list" command. | False |
| Fetch incidents |  | False |
| Output results of old version commands to the context data in the old format |  | False |
| Mirroring Direction | 'Choose the direction to mirror the incident: Incoming (from Prisma Cloud to Cortex XSOAR), Outgoing (from Cortex XSOAR to Prisma Cloud), or Incoming and Outgoing (from/to Cortex XSOAR and Prisma Cloud).' | False |
| Close Mirrored XSOAR Incident | When selected, closing and re-opening the Prisma Cloud alert is mirrored in Cortex XSOAR. | False |
| Close Mirrored Prisma Cloud Alert |  When selected, closing and re-opening the Cortex XSOAR incident is mirrored in Prisma Cloud. | False |



### Incident Mirroring
 
You can enable incident mirroring between Cortex XSOAR incidents and Prisma Cloud alerts (available from Cortex XSOAR version 6.0.0).

To setup the mirroring follow these instructions:

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for **Prisma Cloud v2** and select your integration instance.
3. Enable **Fetches incidents**.
4. Optional: You can go to the *Fetch only incidents matching these filters* parameter and select the query to fetch the alerts from Prisma Cloud.
6. In the *Incident Mirroring Direction* parameter, select in which direction the incidents should be mirrored:
    - Incoming - Changes in Prisma Cloud Alerts (`status`, `dismissalNote`, `reason`) will be reflected in Cortex XSOAR incidents.
    - Outgoing - Changes in Cortex XSOAR incidents will be reflected in Prisma Cloud alerts (`status`, `reason`).
    - Incoming And Outgoing - Changes in Cortex XSOAR incidents and in Prisma Cloud alerts will be reflected in both directions.
    - None - Turns off incident mirroring.
7. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close or reopen the Cortex XSOAR incident when the corresponding alert is closed or re-opened in Prisma Cloud.
8. Optional: Check the *Close Mirrored Prisma Cloud Alert* integration parameter to close or reopen the Prisma Cloud alert when the corresponding Cortex XSOAR incident is closed or re-opened.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.

**Important Notes**

- To ensure the mirroring works as expected, an incoming mapper is required, to map the expected fields in Cortex XSOAR (you can use the default mapper - *Prisma Cloud - Incoming Mapper*).
- When *mirroring in* incidents from Prisma Cloud to Cortex XSOAR:
  - When enabling the *Close Mirrored XSOAR Incident* integration parameter, the field in Prisma Cloud that determines whether the incident was closed or re-opend is the `status` field.
- When *mirroring out* incidents from Cortex XSOAR to Prisma Cloud:
  - When enabling the *Close Mirrored Prisma Cloud Alert* integration parameter, the corresponding alert in Prisma Cloud will be closed with a *Dismissed* status for every reason chosen in the Cortex XSOAR incident (possible reasons are: `False Positive`, `Duplicate`, `Other` and `Resolved`). The *Reason* field of the Prisma Cloud alert will include the original reason selected in Cortex XSOAR and the close notes.
  - When re-opening a Cortex XSOAR incident with a `Resolved` Prisma Cloud status, the incident will be re-opened, but the alert in Prisma Cloud will remain Resolved due to API limitations.  
 
## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### prisma-cloud-alert-dismiss

***
Dismiss or snooze the alerts matching the given filter. Either policy IDs or alert IDs must be provided. When no absolute time nor relative time arguments are provided, the default time range is all times. For snoozing, provide "snooze_unit" and "snooze_value" arguments.

#### Base Command

`prisma-cloud-alert-dismiss`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | Comma-separated list of alert IDs to be dismissed. | Optional | 
| policy_ids | Comma-separated list of policy IDs. | Optional | 
| snooze_value | The amount of time for snoozing alert. Both snooze value and unit must be specified if snoozing. | Optional | 
| snooze_unit | The time unit for snoozing alert. Both snooze value and unit must be specified if snoozing. Possible values are: hour, day, week, month, year. | Optional | 
| dismissal_note | Reason for dismissal. | Required | 
| time_range_date_from | Start time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_date_to | End time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_unit | The search time unit. The "login" and "epoch" options are only available if "time_range_value" is not provided. Possible values are: hour, day, week, month, year, login, epoch. | Optional | 
| time_range_value | The amount of "time_range_unit" to go back in time. For example, 3 days, 5 weeks, etc. | Optional | 
| filters | Comma-separated list of filter name and value, in the following format: filtername1=filtervalue1,filtername2=filtervalue2,etc. Names and possible values for filters can be found by running the "prisma-cloud-alert-filter-list" command. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!prisma-cloud-alert-dismiss dismissal_note="from XSOAR" alert_ids=P-464811 snooze_unit=hour snooze_value=1```
#### Human Readable Output

>### Alerts snoozed successfully.
>Snooze note: from XSOAR.

#### Command example
```!prisma-cloud-alert-dismiss dismissal_note="from XSOAR" alert_ids=P-469663 time_range_unit=month```
#### Human Readable Output

>### Alerts dismissed successfully.
>Dismissal note: from XSOAR.

### prisma-cloud-alert-get-details

***
Gets the details of an alert based on the alert ID.

#### Base Command

`prisma-cloud-alert-get-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID. | Required | 
| detailed | Whether to retrieve the entire / trimmed alert model. Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.Alert.id | String | The alert ID. | 
| PrismaCloud.Alert.status | String | The alert status. | 
| PrismaCloud.Alert.reason | String | The alert reason. | 
| PrismaCloud.Alert.alertTime | Date | The time of the alert. | 
| PrismaCloud.Alert.firstSeen | Date | The time the alert was first seen. | 
| PrismaCloud.Alert.lastSeen | Date | The time the alert was last seen. | 
| PrismaCloud.Alert.eventOccurred | Date | The time the event occurred. | 
| PrismaCloud.Alert.alertRules | String | Names of the alert rules that triggered this alert. | 
| PrismaCloud.Alert.resource.resourceApiName | String | The resource API name. | 
| PrismaCloud.Alert.resource.id | String | The resource ID. | 
| PrismaCloud.Alert.resource.account | String | The resource account. | 
| PrismaCloud.Alert.resource.accountId | String | The resource account ID. | 
| PrismaCloud.Alert.resource.resourceType | String | The resource type. | 
| PrismaCloud.Alert.policy.policyId | String | The policy ID. | 
| PrismaCloud.Alert.policy.name | String | The policy name. | 
| PrismaCloud.Alert.policy.policyType | String | The type of policy. | 
| PrismaCloud.Alert.policy.severity | String | The policy severity. | 
| PrismaCloud.Alert.policy.recommendation | String | The policy recommendation. | 
| PrismaCloud.Alert.policy.remediation.description | String | The policy remediation description. | 
| PrismaCloud.Alert.policy.remediation.cliScriptTemplate | String | The policy remediation CLI script template. | 
| PrismaCloud.Alert.policy.description | String | The policy description. | 
| PrismaCloud.Alert.policy.labels | Unknown | The policy labels. | 
| PrismaCloud.Alert.resource.cloudType | String | The resource cloud type. | 
| PrismaCloud.Alert.resource.rrn | String | The restricted resource name. | 
| PrismaCloud.Alert.resource.regionId | String | The resource region ID. | 
| PrismaCloud.Alert.resource.url | String | The resource URL. | 
| PrismaCloud.Alert.policy.remediable | Boolean | Whether the policy is remediable. | 
| PrismaCloud.Alert.policy.systemDefault | Boolean | Whether the policy is the system default. | 
| PrismaCloud.Alert.policy.deleted | Boolean | Whether the policy was deleted. | 

#### Command example
```!prisma-cloud-alert-get-details alert_id=P-465020```
#### Context Example
```json
{
    "PrismaCloud": {
        "Alert": {
            "alertRules": [
                {
                    "alertRuleNotificationConfig": [],
                    "allowAutoRemediate": false,
                    "enabled": true,
                    "name": "test",
                    "notifyOnDismissed": false,
                    "notifyOnOpen": true,
                    "notifyOnResolved": false,
                    "notifyOnSnoozed": false,
                    "policyScanConfigId": "policy-scan-config-id3",
                    "scanAll": true,
                    "target": {
                        "accountGroups": [],
                        "excludedAccounts": [],
                        "regions": [],
                        "tags": []
                    }
                },
                {
                    "alertRuleNotificationConfig": [],
                    "allowAutoRemediate": false,
                    "enabled": true,
                    "name": "Default Alert Rule",
                    "notifyOnDismissed": false,
                    "notifyOnOpen": true,
                    "notifyOnResolved": false,
                    "notifyOnSnoozed": false,
                    "policyScanConfigId": "policy-scan-config-id2",
                    "scanAll": false,
                    "target": {
                        "accountGroups": [],
                        "excludedAccounts": [],
                        "regions": [],
                        "tags": []
                    }
                }
            ],
            "alertTime": "2023-01-25T19:18:22Z",
            "dismissalNote": "from XSOAR",
            "dismissalUntilTs": -1,
            "dismissedBy": "name@company.com",
            "firstSeen": "2023-01-25T19:18:22Z",
            "history": [
                {
                    "modifiedBy": "name@company.com",
                    "modifiedOn": 1674987271011,
                    "reason": "NEW_ALERT",
                    "status": "open"
                }
            ],
            "id": "P-465020",
            "lastSeen": "2023-01-29T10:14:31Z",
            "metadata": {
                "saveSearchId": "save-search-id1"
            },
            "networkAnomaly": false,
            "policy": {
                "complianceMetadata": [
                    {
                        "complianceId": "compliance-id1",
                        "customAssigned": false,
                        "policyId": "a11b2cc3-1111-2222-33aa-a1b23ccc4dd5",
                        "requirementId": "DSI",
                        "requirementName": "Data Security & Information Lifecycle Management",
                        "requirementViewOrder": 5,
                        "sectionDescription": "Data Inventory / Flows.",
                        "sectionId": "DSI-02",
                        "sectionLabel": "CSA CCM",
                        "sectionViewOrder": 25,
                        "standardDescription": "Cloud Security Alliance: Cloud Controls Matrix Version 3.0.1",
                        "standardName": "CSA CCM v3.0.1",
                        "systemDefault": true
                    },
                    {
                        "complianceId": "compliance-id2",
                        "customAssigned": false,
                        "policyId": "a11b2cc3-1111-2222-33aa-a1b23ccc4dd5",
                        "requirementId": "IAM",
                        "requirementName": "Identity & Access Management",
                        "requirementViewOrder": 10,
                        "sectionDescription": "Third Party Access.",
                        "sectionId": "IAM-07",
                        "sectionLabel": "CSA CCM",
                        "sectionViewOrder": 72,
                        "standardDescription": "Cloud Security Alliance: Cloud Controls Matrix Version 3.0.1",
                        "standardName": "CSA CCM v3.0.1",
                        "systemDefault": true
                    }
                ],
                "deleted": false,
                "description": "This policy identifies GCP VPC Network subnets have disabled Private Google access. Private Google access enables virtual machine instances on a subnet to reach Google APIs and services using an internal IP address rather than an external IP address. Internal (private) IP addresses are internal to Google Cloud Platform and are not routable or reachable over the Internet. You can use Private Google access to allow VMs without Internet access to reach Google APIs, services, and properties that are accessible over HTTP/HTTPS.",
                "findingTypes": [],
                "labels": [
                    "Policy Status Review"
                ],
                "lastModifiedBy": "example@gmail.com",
                "lastModifiedOn": 1664515792712,
                "name": "GCP VPC Network subnets have Private Google access disabled",
                "policyId": "a11b2cc3-1111-2222-33aa-a1b23ccc4dd5",
                "policyType": "config",
                "recommendation": "1. Login to GCP Portal\n2. Go to VPC network (Left Panel)\n3. Select VPC networks\n2. Click on the name of a reported subnet, The 'Subnet details' page will be displayed\n3. Click on 'EDIT' button\n4. Set 'Private Google access' to 'On'\n5. Click on Save",
                "remediable": true,
                "remediation": {
                    "cliScriptTemplate": "gcloud compute networks subnets update ${resourceName} --project=${account} --region ${region} --enable-private-ip-google-access",
                    "description": "This CLI command requires 'compute.networkAdmin' permission. Successful execution will enable GCP VPC Network subnets 'Private Google access'.",
                    "impact": "enables private-ip-google-access in GCP VPC Network subnets"
                },
                "severity": "medium",
                "systemDefault": true
            },
            "reason": "USER_DISMISSED",
            "resource": {
                "account": "mail1@gmail.com",
                "accountId": "panw-prisma-cloud",
                "additionalInfo": {},
                "cloudAccountGroups": [
                    "Default Account Group"
                ],
                "cloudAccountOwners": [
                    "mail1@gmail.com"
                ],
                "cloudServiceName": "Google VPC",
                "cloudType": "gcp",
                "data": {
                    "creationTimestamp": "2023-01-25T08:52:45.111-08:00",
                    "fingerprint": "a-fingerprint=",
                    "gatewayAddress": "1.1.1.1",
                    "id": "1111111111111111111",
                    "ipCidrRange": "1.1.1.1/20",
                    "kind": "compute#subnetwork",
                    "name": "boombox-network",
                    "network": "https://some-url",
                    "privateIpGoogleAccess": false,
                    "purpose": "PRIVATE",
                    "region": "https://some-url",
                    "selfLink": "https://some-url/subnetworks/boombox-network",
                    "stackType": "IPV4_ONLY"
                },
                "id": "1111111111111111111",
                "internalResourceId": "11111111",
                "name": "boombox-network",
                "region": "GCP Belgium",
                "regionId": "europe-west1",
                "resourceApiName": "gcloud-compute-networks-subnets-list",
                "resourceConfigJsonAvailable": true,
                "resourceDetailsAvailable": true,
                "resourceTs": 1676633361033,
                "resourceType": "SUBNET",
                "rrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
                "unifiedAssetId": "unified-asset-id1"
            },
            "saveSearchId": "save-search-id3",
            "status": "dismissed"
        }
    }
}
```

#### Human Readable Output

>### Alert P-465020 Details:
>|Alert ID|Reason|Status|Alert Time|First Seen|Last Seen|Policy ID|Policy Type|Is Policy System Default|Is Policy Remediable|Policy Name|Policy Recommendation|Policy Description|Policy Severity|Policy Remediation Description|Policy Remediation CLI Script|Policy Labels|Resource Type|Resource Account|Resource Cloud Type|Resource RRN|Resource ID|Resource Account ID|Resource Region ID|Resource Api Name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| P-465020 | USER_DISMISSED | dismissed | 2023-01-25T19:18:22Z | 2023-01-25T19:18:22Z | 2023-01-29T10:14:31Z | a11b2cc3-1111-2222-33aa-a1b23ccc4dd5 | config | true | true | GCP VPC Network subnets have Private Google access disabled | 1. Login to GCP Portal<br/>2. Go to VPC network (Left Panel)<br/>3. Select VPC networks<br/>2. Click on the name of a reported subnet, The 'Subnet details' page will be displayed<br/>3. Click on 'EDIT' button<br/>4. Set 'Private Google access' to 'On'<br/>5. Click on Save | This policy identifies GCP VPC Network subnets have disabled Private Google access. Private Google access enables virtual machine instances on a subnet to reach Google APIs and services using an internal IP address rather than an external IP address. Internal (private) IP addresses are internal to Google Cloud Platform and are not routable or reachable over the Internet. You can use Private Google access to allow VMs without Internet access to reach Google APIs, services, and properties that are accessible over HTTP/HTTPS. | medium | This CLI command requires 'compute.networkAdmin' permission. Successful execution will enable GCP VPC Network subnets 'Private Google access'. | gcloud compute networks subnets update ${resourceName} --project=${account} --region ${region} --enable-private-ip-google-access | Policy Status Review | SUBNET | mail1@gmail.com | gcp | rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25 | 1111111111111111111 | panw-prisma-cloud | europe-west1 | gcloud-compute-networks-subnets-list |


### prisma-cloud-alert-filter-list

***
List the acceptable filters and values for alerts.

#### Base Command

`prisma-cloud-alert-filter-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.AlertFilters.filterName | String | The filter name. | 
| PrismaCloud.AlertFilters.options | String | The filter value options. | 
| PrismaCloud.AlertFilters.staticFilter | Unknown | Whether the filter is static. | 

#### Command example
```!prisma-cloud-alert-filter-list```
#### Context Example
```json
{
    "PrismaCloud": {
        "AlertFilters": [
            {
                "filterName": "policy.name",
                "options": [
                    "GCP Kubernetes Engine Clusters have Master authorized networks disabled"
                ],
                "staticFilter": false
            },
            {
                "filterName": "policy.type",
                "options": [
                    "anomaly",
                    "audit_event",
                    "config",
                    "data",
                    "iam",
                    "network",
                    "workload_incident",
                    "workload_vulnerability"
                ],
                "staticFilter": true
            },
            {
                "filterName": "policy.label",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "policy.severity",
                "options": [
                    "critical",
                    "high",
                    "medium",
                    "low",
                    "informational"
                ],
                "staticFilter": true
            },
            {
                "filterName": "policy.complianceStandard",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "policy.complianceRequirement",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "policy.complianceSection",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "cloud.account",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "account.group",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "cloud.region",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "alertRule.name",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "resource.id",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "resource.name",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "resource.type",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "resource.group",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "cloud.service",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "cloud.accountId",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "object.exposure",
                "options": [
                    "private",
                    "public",
                    "conditional"
                ],
                "staticFilter": true
            },
            {
                "filterName": "malware",
                "options": [
                    "true"
                ],
                "staticFilter": true
            },
            {
                "filterName": "object.classification",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "object.identifier",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "timeRange.type",
                "options": [
                    "ALERT_STATUS_UPDATED",
                    "ALERT_UPDATED",
                    "ALERT_OPENED"
                ],
                "staticFilter": true
            },
            {
                "filterName": "vulnerability.severity",
                "options": [
                    "all",
                    "high",
                    "critical",
                    "low",
                    "medium"
                ],
                "staticFilter": true
            },
            {
                "filterName": "buildtime.resourceName",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "git.filename",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "git.provider",
                "options": [
                    "github",
                    "gitlab",
                    "bitbucket",
                    "perforce"
                ],
                "staticFilter": false
            },
            {
                "filterName": "git.repository",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "iac.framework",
                "options": [
                    "ttt",
                    "CloudFormation"
                ],
                "staticFilter": false
            },
            {
                "filterName": "asset.class",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "alert.id",
                "options": [],
                "staticFilter": false
            },
            {
                "filterName": "policy.subtype",
                "options": [
                    "audit",
                    "build",
                    "data_classification",
                    "dns",
                    "identity",
                    "malware",
                    "network",
                    "network_config",
                    "network_event",
                    "permissions",
                    "run",
                    "run_and_build",
                    "ueba"
                ],
                "staticFilter": true
            },
            {
                "filterName": "alert.status",
                "options": [
                    "dismissed",
                    "snoozed",
                    "open",
                    "resolved"
                ],
                "staticFilter": true
            },
            {
                "filterName": "cloud.type",
                "options": [
                    "alibaba_cloud",
                    "aws",
                    "azure",
                    "gcp",
                    "oci"
                ],
                "staticFilter": true
            },
            {
                "filterName": "policy.remediable",
                "options": [
                    "true",
                    "false"
                ],
                "staticFilter": true
            }
        ]
    }
}
```

#### Human Readable Output

>### Filter Options:
>|Filter Name|Options|Static Filter|
>|---|---|---|
>| policy.name | GCP Kubernetes Engine Clusters have Master authorized networks disabled | false |
>| policy.type | anomaly,<br/>audit_event,<br/>config,<br/>data,<br/>iam,<br/>network,<br/>workload_incident,<br/>workload_vulnerability | true |
>| policy.label |  | false |
>| policy.severity | critical,<br/>high,<br/>medium,<br/>low,<br/>informational | true |
>| policy.complianceStandard |  | false |
>| policy.complianceRequirement |  | false |
>| policy.complianceSection |  | false |
>| cloud.account |  | false |
>| account.group |  | false |
>| cloud.region |  | false |
>| alertRule.name |  | false |
>| resource.id |  | false |
>| resource.name |  | false |
>| resource.type |  | false |
>| resource.group |  | false |
>| cloud.service |  | false |
>| cloud.accountId |  | false |
>| object.exposure | private,<br/>public,<br/>conditional | true |
>| malware | true | true |
>| object.classification |  | false |
>| object.identifier |  | false |
>| timeRange.type | ALERT_STATUS_UPDATED,<br/>ALERT_UPDATED,<br/>ALERT_OPENED | true |
>| vulnerability.severity | all,<br/>high,<br/>critical,<br/>low,<br/>medium | true |
>| buildtime.resourceName |  | false |
>| git.filename |  | false |
>| git.provider | github,<br/>gitlab,<br/>bitbucket,<br/>perforce | false |
>| git.repository |  | false |
>| iac.framework | ttt,<br/>CloudFormation | false |
>| asset.class |  | false |
>| alert.id |  | false |
>| policy.subtype | audit,<br/>build,<br/>data_classification,<br/>dns,<br/>identity,<br/>malware,<br/>network,<br/>network_config,<br/>network_event,<br/>permissions,<br/>run,<br/>run_and_build,<br/>ueba | true |
>| alert.status | dismissed,<br/>snoozed,<br/>open,<br/>resolved | true |
>| cloud.type | alibaba_cloud,<br/>aws,<br/>azure,<br/>gcp,<br/>oci | true |
>| policy.remediable | true,<br/>false | true |


### prisma-cloud-remediation-command-list

***
Generates and returns a list of remediation commands for the specified alerts and policies. Data returned for a successful call include fully constructed commands for remediation. Either a policy ID or alert IDs must be provided. The returned information can be retrieved in the UI by clicking the "Remediate" button under the "Actions" column for supported alerts. When no absolute time nor relative time arguments are provided, the default time range is all times.

#### Base Command

`prisma-cloud-remediation-command-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | Comma-seperated list of alert IDs for which to get remediation details. Provided alert IDs must be associated with the same policy. If a policy is specified, all the alerts specified must belong to that policy. | Optional | 
| policy_id | Policy ID for which to get remediation details. | Optional | 
| time_range_date_from | Start time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_date_to | End time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_unit | The search time unit. The "login" and "epoch" options are only available if "time_range_value" is not provided. Possible values are: hour, day, week, month, year, login, epoch. | Optional | 
| time_range_value | The amount of "time_range_unit" to go back in time. For example, 3 days, 5 weeks, etc. | Optional | 
| limit | Maximum number of entries to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.AlertRemediation.description | String | Description of CLI remediation instructions. | 
| PrismaCloud.AlertRemediation.scriptImpact | String | Impact of CLI remediation instructions. | 
| PrismaCloud.AlertRemediation.alertId | String | The ID of the alert to which the remediation details apply. | 
| PrismaCloud.AlertRemediation.CLIScript | String | The exact CLI command string. | 

#### Command example
```!prisma-cloud-remediation-command-list policy_id=a11b2cc3-1111-2222-33aa-a1b23ccc4dd5 limit=2```
#### Context Example
```json
{
    "PrismaCloud": {
        "Alert": {
            "Remediation": [
                {
                    "CLIScript": "aws rds modify-db-instance --db-instance-identifier aaaaaaaaaaaaaa --region us-east-1 --deletion-protection",
                    "alertId": "P-351515",
                    "description": "This CLI command requires 'rds:ModifyDBInstance' permission. Successful execution will enable deletion protection for the reported AWS RDS instance.",
                    "scriptImpact": null
                },
                {
                    "CLIScript": "aws rds modify-db-instance --db-instance-identifier bbbbbbbbbbbbbbb --region us-east-1 --deletion-protection",
                    "alertId": "P-351323",
                    "description": "This CLI command requires 'rds:ModifyDBInstance' permission. Successful execution will enable deletion protection for the reported AWS RDS instance.",
                    "scriptImpact": null
                }
            ]
        }
    }
}
```

#### Human Readable Output

>Showing 2 of 3 results:
>### Remediation Command List:
>|CLI Script|Alert Id|Description|
>|---|---|---|
>| aws rds modify-db-instance --db-instance-identifier aaaaaaaaaaaaaa --region us-east-1 --deletion-protection | P-351515 | This CLI command requires 'rds:ModifyDBInstance' permission. Successful execution will enable deletion protection for the reported AWS RDS instance. |
>| aws rds modify-db-instance --db-instance-identifier bbbbbbbbbbbbbbb --region us-east-1 --deletion-protection | P-351323 | This CLI command requires 'rds:ModifyDBInstance' permission. Successful execution will enable deletion protection for the reported AWS RDS instance. |


### prisma-cloud-alert-remediate

***
Remediates the alert with the specified ID, if that alert is associated with a remediable policy. In order to check what remediation would run, use the "prisma-cloud-remediation-command-list" command first.

#### Base Command

`prisma-cloud-alert-remediate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.AlertRemediation.alertId | String | The ID of the alert to which the remediation apply. | 
| PrismaCloud.AlertRemediation.successful | Boolean | Whether the remediation was successful. | 
| PrismaCloud.AlertRemediation.failureReason | String | The failure reason for the remediation. | 
| PrismaCloud.AlertRemediation.errorValue | String | The error value for the remediation. | 

#### Command example
```!prisma-cloud-alert-remediate alert_id=P-488074```
#### Context Example
```json
{
    "PrismaCloud": {
        "AlertRemediation": {
            "alertId": "P-488074",
            "successful": true
        }
    }
}
```

#### Human Readable Output

>Alert P-488074 remediated successfully.

### prisma-cloud-alert-reopen

***
Re-open the alerts matching the given filter. Either policy IDs or alert IDs must be provided. When no absolute time nor relative time arguments are provided, the default time range is all times.

#### Base Command

`prisma-cloud-alert-reopen`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | Comma-separated list of alert IDs to be reopened. | Optional | 
| policy_ids | Comma-separated list of policy IDs. | Optional | 
| time_range_date_from | Start time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_date_to | End time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_unit | The search time unit. The "login" and "epoch" options are only available if "time_range_value" is not provided. Possible values are: hour, day, week, month, year, login, epoch. | Optional | 
| time_range_value | The amount of "time_range_unit" to go back in time. For example, 3 days, 5 weeks, etc. | Optional | 
| filters | Comma-separated list of filter name and value, in the following format: filtername1=filtervalue1,filtername2=filtervalue2,etc. Names and possible values for filters can be found by running the "prisma-cloud-alert-filter-list" command. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!prisma-cloud-alert-reopen alert_ids=P-469663```
#### Human Readable Output

>### Alerts re-opened successfully.

### prisma-cloud-alert-search

***
Search alerts on the Prisma Cloud platform. When no absolute time nor relative time arguments are provided, the search will show alerts from the last 7 days.

#### Base Command

`prisma-cloud-alert-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range_date_from | Start time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_date_to | End time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_unit | The search time unit. The "login" and "epoch" options are only available if "time_range_value" is not provided. Possible values are: hour, day, week, month, year, login, epoch. | Optional | 
| time_range_value | The amount of "time_range_unit" to go back in time. For example, 3 days, 5 weeks, etc. | Optional | 
| filters | Comma-separated list of filter name and value, in the following format: filtername1=filtervalue1,filtername2=filtervalue2,etc. Names and possible values for filters can be found by running the "prisma-cloud-alert-filter-list" command. | Optional | 
| detailed | Whether to retrieve the entire / trimmed alert model. Possible values are: true, false. Default is true. | Optional | 
| limit | Maximum number of entries to return. Default is 50. | Optional | 
| next_token | Token of the next page to retrive. When provided, other arguments are ignored. | Optional | 
| sort_field | The field to sort the results by. Possible values are: alertTime,firstSeen,lastSeen,lastUpdated. | Optional | 
| sort_direction | The direction to sort the results by. Sort field must be specified if sorting. Possible values are: asc, desc. Default is asc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.AlertPageToken.nextPageToken | String | Next page token. | 
| PrismaCloud.Alert.id | String | The ID of the returned alert. | 
| PrismaCloud.Alert.status | String | The status of the returned alert. | 
| PrismaCloud.Alert.reason | String | The reason of the returned alert. | 
| PrismaCloud.Alert.lastSeen | String | The time the returned alert was last seen. | 
| PrismaCloud.Alert.firstSeen | String | The time the returned alert was first seen. | 
| PrismaCloud.Alert.lastUpdated | String | The time the returned alert was last updated. | 
| PrismaCloud.Alert.alertTime | String | The time of the returned alert. | 
| PrismaCloud.Alert.policy.policyId | String | The policy ID of the returned alert. | 
| PrismaCloud.Alert.policy.name | String | The policy name of the returned alert. | 
| PrismaCloud.Alert.policy.policyType | String | The policy type of the returned alert. | 
| PrismaCloud.Alert.policy.severity | String | The policy severity of the returned alert. | 
| PrismaCloud.Alert.policy.remediable | Boolean | Whether the policy is remediable. | 
| PrismaCloud.Alert.policy.description | String | The policy description of the returned alert. | 
| PrismaCloud.Alert.policy.recommendation | String | The policy recommendation of the returned alert. | 
| PrismaCloud.Alert.policy.remediation.description | String | The policy remediation description of the returned alert. | 
| PrismaCloud.Alert.policy.remediation.cliScriptTemplate | String | The policy CLI script template description of the returned alert. | 
| PrismaCloud.Alert.policy.systemDefault | Boolean | Whether the policy is the system default. | 
| PrismaCloud.Alert.policy.deleted | Boolean | Whether the policy was deleted. | 
| PrismaCloud.Alert.resource.resourceType | String | The resource type of the returned alert. | 
| PrismaCloud.Alert.resource.name | String | The resource name of the returned alert. | 
| PrismaCloud.Alert.resource.account | String | The resource account of the returned alert. | 
| PrismaCloud.Alert.resource.cloudType | String | The resource cloud type of the returned alert. | 
| PrismaCloud.Alert.resource.rrn | String | The restricted resource name of the returned alert. | 

#### Command example
```!prisma-cloud-alert-search filters=alert.status=open,policy.remediable=true,cloud.type=gcp,policy.type=config limit=2```
#### Context Example
```json
{
    "PrismaCloud": {
        "Alert": [
            {
                "alertRules": [],
                "alertTime": "2023-02-17T12:57:46Z",
                "firstSeen": "2023-02-17T12:57:46Z",
                "history": [],
                "id": "P-487678",
                "lastSeen": "2023-02-17T12:57:46Z",
                "lastUpdated": "2023-02-19T13:27:29Z",
                "metadata": {
                    "saveSearchId": "save-search-id2"
                },
                "policy": {
                    "complianceMetadata": [
                        {
                            "complianceId": "compliance-id1",
                            "customAssigned": false,
                            "policyId": "policy-id2",
                            "requirementId": "DSI",
                            "requirementName": "Data Security & Information Lifecycle Management",
                            "requirementViewOrder": 5,
                            "sectionDescription": "Data Inventory / Flows.",
                            "sectionId": "DSI-02",
                            "sectionLabel": "CSA CCM",
                            "sectionViewOrder": 25,
                            "standardDescription": "Cloud Security Alliance: Cloud Controls Matrix Version 3.0.1",
                            "standardName": "CSA CCM v3.0.1",
                            "systemDefault": true
                        },
                        {
                            "complianceId": "compliance-id2",
                            "customAssigned": false,
                            "policyId": "policy-id4",
                            "requirementId": "IAM",
                            "requirementName": "Identity & Access Management",
                            "requirementViewOrder": 10,
                            "sectionDescription": "Third Party Access.",
                            "sectionId": "IAM-07",
                            "sectionLabel": "CSA CCM",
                            "sectionViewOrder": 72,
                            "standardDescription": "Cloud Security Alliance: Cloud Controls Matrix Version 3.0.1",
                            "standardName": "CSA CCM v3.0.1",
                            "systemDefault": true
                        }
                    ],
                    "deleted": false,
                    "description": "This policy identifies GCP Firewall rule allowing all traffic on read-only port (12346) which exposes GKE clusters. In GKE, Kubelet exposes a read-only port 12346 which shows the configurations of all pods on the cluster at the /pods API endpoint. GKE itself does not expose this port to the Internet as the default project firewall configuration blocks external access. However, it is possible to inadvertently expose this port publicly on GKE clusters by creating a Google Compute Engine VPC firewall for GKE nodes that allows traffic from all source ranges on all the ports. This configuration publicly exposes all pod configurations, which might contain sensitive information.",
                    "findingTypes": [],
                    "labels": [],
                    "lastModifiedBy": "example@gmail.com",
                    "lastModifiedOn": 1649907869989,
                    "name": "GCP Firewall rule exposes GKE clusters by allowing all traffic on read-only port (12346)",
                    "policyId": "policy-id5",
                    "policyType": "config",
                    "recommendation": "As port 12345 exposes sensitive information of GKE pod configuration it is recommended to disable this firewall rule. \nOtherwise, remove the overly permissive source IPs following below steps,\n\n1. Login to GCP Console\n2. Navigate to 'VPC Network'(Left Panel)\n3. Go to the 'Firewall' section (Left Panel)\n4. Click on the reported Firewall rule\n5. Click on 'EDIT'\n6. Modify Source IP ranges to specific IP\n7. Click on 'SAVE'.",
                    "remediable": true,
                    "remediation": {
                        "cliScriptTemplate": "gcloud compute --project=${account} firewall-rules update ${resourceName} --disabled",
                        "description": "This CLI command requires 'compute.firewalls.update' and 'compute.networks.updatePolicy' permission. Successful execution will disable this firewall rule blocking internet traffic to port 12346.",
                        "impact": "Disable GCP Firewall rule which allows all traffic on read-only port (12345)"
                    },
                    "severity": "medium",
                    "systemDefault": true
                },
                "policyId": "policy-id7",
                "reason": "NEW_ALERT",
                "resource": {
                    "account": "Google Cloud Account",
                    "accountId": "AAAAAAA",
                    "additionalInfo": {},
                    "cloudAccountGroups": [
                        "Default Account Group"
                    ],
                    "cloudAccountOwners": [
                        "mail1@gmail.com",
                        "example@gmail.com"
                    ],
                    "cloudServiceName": "Google VPC",
                    "cloudType": "gcp",
                    "data": {
                        "allowed": [
                            {
                                "IPProtocol": "all"
                            }
                        ],
                        "creationTimestamp": "2022-09-19T21:28:10.104-07:00",
                        "description": "",
                        "direction": "INGRESS",
                        "disabled": false,
                        "id": "666666666666666666",
                        "kind": "compute#firewall",
                        "logConfig": {
                            "enable": false
                        },
                        "name": "k8s",
                        "network": "https://some-url",
                        "priority": 1000,
                        "selfLink": "https://some-url",
                        "sourceRanges": [
                            "0.0.0.0/0"
                        ]
                    },
                    "id": "3333333333333333333",
                    "name": "k8s",
                    "region": "global",
                    "regionId": "global",
                    "resourceApiName": "gcloud-compute-firewall-rules-list",
                    "resourceConfigJsonAvailable": true,
                    "resourceDetailsAvailable": true,
                    "resourceTs": 1676633555070,
                    "resourceType": "SECURITY_GROUP",
                    "rrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
                    "unifiedAssetId": "unifiedassetid2"
                },
                "saveSearchId": "save-search-id5",
                "status": "open"
            },
            {
                "alertRules": [],
                "alertTime": "2023-02-17T12:57:46Z",
                "firstSeen": "2023-02-17T12:57:46Z",
                "history": [],
                "id": "P-487768",
                "lastSeen": "2023-02-17T12:57:46Z",
                "lastUpdated": "2023-02-19T13:27:29Z",
                "metadata": {
                    "saveSearchId": "save-search-id5"
                },
                "policy": {
                    "complianceMetadata": [
                        {
                            "complianceId": "compliance-id5",
                            "customAssigned": false,
                            "policyId": "policy-id-4",
                            "requirementId": "Section 404",
                            "requirementName": "Management Assessment",
                            "requirementViewOrder": 3,
                            "sectionDescription": "(b) Evaluation and Reporting.",
                            "sectionId": "Section 404.B",
                            "sectionLabel": "Section 404.B",
                            "sectionViewOrder": 9,
                            "standardDescription": "Management",
                            "standardName": "Management",
                            "systemDefault": true
                        }
                    ],
                    "deleted": false,
                    "description": "This policy identifies GCP Firewall rule allowing all traffic on port 12345 which allows GKE full node access. The port 12345 on the kubelet is used by the kube-apiserver (running on hosts labelled as Orchestration Plane) for exec and logs. As per security best practice, port 12345 should not be exposed to the public.",
                    "findingTypes": [],
                    "labels": [],
                    "lastModifiedBy": "example@gmail.com",
                    "lastModifiedOn": 1652328910000,
                    "name": "GCP Firewall rule exposes GKE clusters by allowing all traffic on port 12345",
                    "policyId": "policy-id5",
                    "policyType": "config",
                    "recommendation": "As port 12345 exposes sensitive information of GKE pod configuration it is recommended to disable this firewall rule. \nOtherwise, remove the overly permissive source IPs following the below steps,\n\n1. Login to GCP Console\n2. Navigate to 'VPC Network'(Left Panel)\n3. Go to the 'Firewall' section (Left Panel)\n4. Click on the reported Firewall rule\n5. Click on 'EDIT'\n6. Modify Source IP ranges to specific IP\n7. Click on 'SAVE'.",
                    "remediable": true,
                    "remediation": {
                        "cliScriptTemplate": "gcloud compute --project=${account} firewall-rules update ${resourceName} --disabled",
                        "description": "This CLI command requires 'compute.firewalls.update' and 'compute.networks.updatePolicy' permission. Successful execution will disable this firewall rule blocking internet traffic to port 12345.",
                        "impact": "disable GCP Firewall rule that allows all traffic on port 12345"
                    },
                    "severity": "medium",
                    "systemDefault": true
                },
                "policyId": "policy-id-2",
                "reason": "NEW_ALERT",
                "resource": {
                    "account": "Google Cloud Account",
                    "accountId": "AAAAAAA",
                    "additionalInfo": {},
                    "cloudAccountGroups": [
                        "AAAAAAA",
                        "Default Account Group"
                    ],
                    "cloudAccountOwners": [
                        "mail1@gmail.com",
                        "example@gmail.com"
                    ],
                    "cloudServiceName": "Google VPC",
                    "cloudType": "gcp",
                    "data": {
                        "allowed": [
                            {
                                "IPProtocol": "all"
                            }
                        ],
                        "creationTimestamp": "2022-09-19T21:28:10.104-07:00",
                        "description": "",
                        "direction": "INGRESS",
                        "disabled": false,
                        "id": "7777777777777777777",
                        "kind": "compute#firewall",
                        "logConfig": {
                            "enable": false
                        },
                        "name": "k8s",
                        "network": "https://some-url/global/networks/default",
                        "priority": 1000,
                        "selfLink": "https://some-url/global/firewalls/k8s",
                        "sourceRanges": [
                            "0.0.0.0/0"
                        ]
                    },
                    "id": "7777777777777777777",
                    "name": "k8s",
                    "region": "global",
                    "regionId": "global",
                    "resourceApiName": "gcloud-compute-firewall-rules-list",
                    "resourceConfigJsonAvailable": true,
                    "resourceDetailsAvailable": true,
                    "resourceTs": 1676633555070,
                    "resourceType": "SECURITY_GROUP",
                    "rrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
                    "unifiedAssetId": "unifiedassetid6"
                },
                "saveSearchId": "save-search-id6",
                "status": "open"
            }
        ],
        "AlertPageToken": {
            "nextPageToken": "token"
        }
    }
}
```

#### Human Readable Output

>Showing 2 of 25 results:
>### Alerts Details:
>|Alert ID|Reason|Status|Alert Time|First Seen|Last Seen|Last Updated|Policy ID|Policy Type|Is Policy System Default|Is Policy Remediable|Policy Name|Is Policy Deleted|Policy Recommendation|Policy Description|Policy Severity|Policy Remediation Description|Policy Remediation CLI Script|Resource Type|Resource Name|Resource Account|Resource Cloud Type|Resource RRN|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| P-487678 | NEW_ALERT | open | 2023-02-17T12:57:46Z | 2023-02-17T12:57:46Z | 2023-02-17T12:57:46Z | 2023-02-19T13:27:29Z | policy-id7 | config | true | true | GCP Firewall rule exposes GKE clusters by allowing all traffic on read-only port (12346) | false | As port 12346 exposes sensitive information of GKE pod configuration it is recommended to disable this firewall rule. <br/>Otherwise, remove the overly permissive source IPs following below steps,<br/><br/>1. Login to GCP Console<br/>2. Navigate to 'VPC Network'(Left Panel)<br/>3. Go to the 'Firewall' section (Left Panel)<br/>4. Click on the reported Firewall rule<br/>5. Click on 'EDIT'<br/>6. Modify Source IP ranges to specific IP<br/>7. Click on 'SAVE'. | This policy identifies GCP Firewall rule allowing all traffic on read-only port (12346) which exposes GKE clusters. In GKE, Kubelet exposes a read-only port 12346 which shows the configurations of all pods on the cluster at the /pods API endpoint. GKE itself does not expose this port to the Internet as the default project firewall configuration blocks external access. However, it is possible to inadvertently expose this port publicly on GKE clusters by creating a Google Compute Engine VPC firewall for GKE nodes that allows traffic from all source ranges on all the ports. This configuration publicly exposes all pod configurations, which might contain sensitive information. | medium | This CLI command requires 'compute.firewalls.update' and 'compute.networks.updatePolicy' permission. Successful execution will disable this firewall rule blocking internet traffic to port 12346. | gcloud compute --project=${account} firewall-rules update ${resourceName} --disabled | SECURITY_GROUP | k8s | Google Cloud Account | gcp | rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25 |
>| P-487768 | NEW_ALERT | open | 2023-02-17T12:57:46Z | 2023-02-17T12:57:46Z | 2023-02-17T12:57:46Z | 2023-02-19T13:27:29Z | policy-id-2 | config | true | true | GCP Firewall rule exposes GKE clusters by allowing all traffic on port 12345 | false | As port 12345 exposes sensitive information of GKE pod configuration it is recommended to disable this firewall rule. <br/>Otherwise, remove the overly permissive source IPs following the below steps,<br/><br/>1. Login to GCP Console<br/>2. Navigate to 'VPC Network'(Left Panel)<br/>3. Go to the 'Firewall' section (Left Panel)<br/>4. Click on the reported Firewall rule<br/>5. Click on 'EDIT'<br/>6. Modify Source IP ranges to specific IP<br/>7. Click on 'SAVE'. | This policy identifies GCP Firewall rule allowing all traffic on port 12345 which allows GKE full node access. The port 12345 on the kubelet is used by the kube-apiserver (running on hosts labelled as Orchestration Plane) for exec and logs. As per security best practice, port 12345 should not be exposed to the public. | medium | This CLI command requires 'compute.firewalls.update' and 'compute.networks.updatePolicy' permission. Successful execution will disable this firewall rule blocking internet traffic to port 12345. | gcloud compute --project=${account} firewall-rules update ${resourceName} --disabled | SECURITY_GROUP | k8s | Google Cloud Account | gcp | rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25 |
>### Next Page Token:
>token

### prisma-cloud-config-search

***
Search configuration inventory on the Prisma Cloud platform using RQL language. Use this command for all queries that start with "config". When no absolute time nor relative time arguments are provided, the default time range is all times.

#### Base Command

`prisma-cloud-config-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range_date_from | Start time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_date_to | End time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_unit | The search time unit. The "login" and "epoch" options are only available if "time_range_value" is not provided. Possible values are: hour, day, week, month, year, login, epoch. | Optional | 
| time_range_value | The amount of "time_range_unit" to go back in time. For example, 3 days, 5 weeks, etc. | Optional | 
| query | Query to run in Prisma Cloud config API using RQL language. For more information see: https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-rql-reference/rql-reference/config-query. | Required | 
| limit | Maximum number of entries to return. Default is 50. | Optional | 
| search_id | Search ID. Can be used to rerun the same search. | Optional | 
| sort_direction | The direction to sort the results by. Both sort direction and field must be specified if sorting. Possible values are: asc, desc. Default is desc. | Optional | 
| sort_field | The field to sort the results by. Both sort direction and field must be specified if sorting. Possible values are: id, time, apiName, customerId, insertTs, json, cloudAccount, cloudRegion, stateId. Default is insertTs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.Config.accountId | String | Cloud account ID. | 
| PrismaCloud.Config.accountName | String | Cloud account name. | 
| PrismaCloud.Config.allowDrillDown | Boolean | Whether to allow drill down. | 
| PrismaCloud.Config.cloudType | String | Cloud type. | 
| PrismaCloud.Config.deleted | Boolean | Whether the asset was deleted. | 
| PrismaCloud.Config.hasExtFindingRiskFactors | Boolean | Whether the configuration has external finding risk factors. | 
| PrismaCloud.Config.hasExternalFinding | Boolean | Whether the configuration has an external finding. | 
| PrismaCloud.Config.hasExternalIntegration | Boolean | Whether the configuration has an external integration. | 
| PrismaCloud.Config.hasNetwork | Boolean | Whether the configuration has a network. | 
| PrismaCloud.Config.id | String | Prisma Cloud configuration ID. | 
| PrismaCloud.Config.assetId | String | Prisma Cloud asset ID. | 
| PrismaCloud.Config.data | Unknown | Prisma Cloud asset specific data. | 
| PrismaCloud.Config.insertTs | Date | Insert timestamp. | 
| PrismaCloud.Config.createdTs | Date | Created timestamp. | 
| PrismaCloud.Config.name | String | Asset name. | 
| PrismaCloud.Config.regionId | String | Cloud region ID. | 
| PrismaCloud.Config.regionName | String | Cloud region name. | 
| PrismaCloud.Config.resourceType | String | Cloud resource type. | 
| PrismaCloud.Config.rrn | String | Cloud restricted resource name. | 
| PrismaCloud.Config.service | String | Cloud service. | 
| PrismaCloud.Config.stateId | String | State ID. | 

#### Command example
```!prisma-cloud-config-search query="config from cloud.resource where cloud.region = 'AWS Ohio' " limit=1```
#### Context Example
```json
{
    "PrismaCloud": {
        "Config": {
            "accountId": "888888888888",
            "accountName": "labs",
            "allowDrillDown": true,
            "assetId": "assetid1",
            "cloudType": "aws",
            "createdTs": "2023-02-17T11:07:40Z",
            "data": {
                "status": {
                    "isLogging": true,
                    "latestCloudWatchLogsDeliveryTime": "2023-02-19T13:27:38.122Z",
                    "latestDeliveryAttemptSucceeded": "2023-02-19T13:28:24Z",
                    "latestDeliveryAttemptTime": "2023-02-19T13:28:24Z",
                    "latestDeliveryTime": "2023-02-19T13:28:24.465Z",
                    "latestDigestDeliveryTime": "2023-02-19T12:40:04.109Z",
                    "latestNotificationAttemptSucceeded": "2023-02-19T13:28:24Z",
                    "latestNotificationAttemptTime": "2023-02-19T13:28:24Z",
                    "latestNotificationTime": "2023-02-19T13:28:24.461Z",
                    "logging": true,
                    "startLoggingTime": "2022-05-25T10:51:34.851Z",
                    "timeLoggingStarted": "2022-05-25T10:51:34Z",
                    "timeLoggingStopped": ""
                },
                "trail": "control"
            },
            "deleted": false,
            "hasExtFindingRiskFactors": false,
            "hasExternalFinding": false,
            "hasExternalIntegration": false,
            "hasNetwork": false,
            "id": "arn:aws:trail:us-west-1:888888888888:trail/control",
            "insertTs": "2023-02-19T13:29:28Z",
            "name": "trail-status",
            "regionId": "us-east-1",
            "regionName": "AWS Ohio",
            "resourceConfigJsonAvailable": true,
            "resourceType": "Cloud Trail Status",
            "rrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
            "service": "AWS CloudTrail",
            "stateId": "stateid3"
        }
    }
}
```

#### Human Readable Output

>Showing 1 of 2925 results:
>### Configuration Details:
>|Name|Id|Cloud Type|Service|Account Name|Region Name|Deleted|Account Id|Asset Id|Created Ts|Insert Ts|Region Id|Resource Type|Rrn|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| control-trail-status | arn:aws:trail:us-west-1:888888888888:trail/control | aws | AWS CloudTrail | labs | AWS Ohio | false | 888888888888 | assetid1 | 2023-02-17T11:07:40Z | 2023-02-19T13:29:28Z | us-east-2 | Cloud Trail Status | rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25 |


### prisma-cloud-event-search

***
Search events inventory on the Prisma Cloud platform using RQL language. Use this command for all queries that start with "event". When no absolute time nor relative time arguments are provided, the default time range is all times.

#### Base Command

`prisma-cloud-event-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range_date_from | Start time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_date_to | End time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_unit | The search time unit. The "login" and "epoch" options are only available if "time_range_value" is not provided. Possible values are: hour, day, week, month, year, login, epoch. | Optional | 
| time_range_value | The amount of "time_range_unit" to go back in time. For example, 3 days, 5 weeks, etc. | Optional | 
| query | Query to run in Prisma Cloud event API using RQL language. For more information see: https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-rql-reference/rql-reference/event-query. | Required | 
| limit | Maximum number of entries to return. Default is 50. | Optional | 
| sort_field | The field to sort the results by. Possible values are: cloudService, operation, cloudAccount, cloudRegion, id, time, crud, user. | Optional | 
| sort_direction | The direction to sort the results by. Sort field must be specified if sorting. Possible values are: asc, desc. Default is asc. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.Event.subject | String | Cloud event subject. | 
| PrismaCloud.Event.accountName | String | Cloud event account name. | 
| PrismaCloud.Event.name | String | Cloud event name. | 
| PrismaCloud.Event.source | String | Cloud event source. | 
| PrismaCloud.Event.ip | String | Cloud event IP address. | 
| PrismaCloud.Event.eventTs | Date | Cloud event timestamp. | 
| PrismaCloud.Event.countryName | String | Cloud event country name. | 
| PrismaCloud.Event.stateName | String | Cloud event state name. | 
| PrismaCloud.Event.cityName | String | Cloud event city name. | 
| PrismaCloud.Event.location | String | Cloud event location. | 
| PrismaCloud.Event.account | String | Cloud event account. | 
| PrismaCloud.Event.regionId | Number | Cloud event region ID. | 
| PrismaCloud.Event.type | String | Cloud event type. | 
| PrismaCloud.Event.id | Number | Cloud event ID. | 
| PrismaCloud.Event.role | String | Cloud event role. | 
| PrismaCloud.Event.accessKeyUsed | Boolean | Whether the cloud event access key is used. | 
| PrismaCloud.Event.success | Boolean | Whether the cloud event is successful. | 
| PrismaCloud.Event.internal | Boolean | Whether the cloud event is internal. | 
| PrismaCloud.Event.cityId | Number | Cloud event city ID. | 
| PrismaCloud.Event.cityLatitude | Number | Cloud event city latitude. | 
| PrismaCloud.Event.cityLongitude | Number | Cloud event city longitude. | 
| PrismaCloud.Event.countryId | Number | Cloud event country ID. | 
| PrismaCloud.Event.dynamicData | String | Cloud event dynamic data. | 
| PrismaCloud.Event.stateId | Number | Cloud event state ID. | 

#### Command example
```!prisma-cloud-event-search query="event from cloud.audit_logs where cloud.type = 'aws'" limit=2```
#### Context Example
```json
{
    "PrismaCloud": {
        "Event": [
            {
                "accessKeyUsed": false,
                "account": "111111111111",
                "accountName": "AAAAAAA",
                "cityId": -3,
                "cityLatitude": -1,
                "cityLongitude": -1,
                "cityName": "Internal",
                "countryId": -3,
                "countryName": "Internal",
                "dynamicData": {},
                "eventTs": "2022-10-17T00:00:26Z",
                "id": 222222222,
                "internal": false,
                "location": "Internal",
                "name": "StartBuild",
                "notPersisted": false,
                "regionId": 2,
                "regionName": "AWS Ohio",
                "role": "CloudWatchEventRule",
                "source": "codebuild",
                "stateId": -3,
                "stateName": "Internal",
                "subject": "Subject3",
                "success": true,
                "type": "CREATE"
            },
            {
                "accessKeyUsed": false,
                "account": "111111111111",
                "accountName": "AAAAAAA",
                "cityId": 4509177,
                "cityLatitude": -1,
                "cityLongitude": -1,
                "cityName": "Columbus",
                "countryId": 6251111,
                "countryName": "United States of America",
                "dynamicData": {},
                "eventTs": "2022-10-17T00:03:07Z",
                "id": 333333333,
                "internal": false,
                "ip": "1.1.1.1",
                "location": "Columbus, Ohio, United States of America",
                "name": "CreateReportGroup",
                "notPersisted": false,
                "regionId": 2,
                "regionName": "AWS Ohio",
                "role": "aws-codebuild-samples",
                "source": "codebuild",
                "stateId": 6666666,
                "stateName": "Ohio",
                "subject": "Subject6",
                "success": false,
                "type": "CREATE"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 2 of 39018 results:
>### Event Details:
>|Subject|Account Name|Name|Source|Ip|Event Ts|Country Name|State Name|City Name|Location|Account|Region Id|Type|Id|Role|Access Key Used|Success|Internal|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Subject3 | AAAAAAA | StartBuild | codebuild |  | 2022-10-17T00:00:26Z | Internal | Internal | Internal | Internal | 111111111111 | 2 | CREATE | 222222222 | CloudWatchEventRule | false | true | false |
>| Subject6 | AAAAAAA | CreateReportGroup | codebuild | 1.1.1.1 | 2022-10-17T00:03:07Z | United States of America | Ohio | Columbus | Columbus, Ohio, United States of America | 111111111111 | 2 | CREATE | 333333333 | aws-codebuild-samples | false | false | false |


### prisma-cloud-network-search

***
Search networks inventory on the Prisma Cloud platform using RQL language. Use this command for all queries that start with "networks". When no absolute time nor relative time arguments are provided, the default time range is all times. In order to limit the results returning, use "limit search records to" at the end of the RQL query, followed by a value from one of these options: 1, 10, 100, 1000, and 10,000.

#### Base Command

`prisma-cloud-network-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range_date_from | Start time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_date_to | End time for the search. Time is interpreted as UTC. Values can be in either ISO date format, relative time, or epoch timestamp. For example: "2019-10-21T23:45:00 GMT+3" (ISO date format), "3 days" (relative time), 1579039377301 (epoch time). | Optional | 
| time_range_unit | The search time unit. The "login" and "epoch" options are only available if "time_range_value" is not provided. Possible values are: hour, day, week, month, year, login, epoch. | Optional | 
| time_range_value | The amount of "time_range_unit" to go back in time. For example, 3 days, 5 weeks, etc. | Optional | 
| query | Query to run in Prisma Cloud network API using RQL language. For more information see: https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-rql-reference/rql-reference/network-query. | Required | 
| cloud_type | The cloud in which the network should be searched. Possible values are: aws, azure, gcp, alibaba_cloud, oci. | Optional | 
| search_id | Search ID. Can be used to rerun the same search. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.Network.Node.id | Number | Cloud network node ID. | 
| PrismaCloud.Network.Node.name | String | Cloud network node name. | 
| PrismaCloud.Network.Node.ipAddr | String | Cloud network node IP address. | 
| PrismaCloud.Network.Node.grouped | Boolean | Whether the cloud network node is grouped. | 
| PrismaCloud.Network.Node.suspicious | Boolean | Whether the cloud network node is suspicious. | 
| PrismaCloud.Network.Node.vulnerable | Boolean | Whether the cloud network node is vulnerable. | 
| PrismaCloud.Network.Node.metadata | Unknown | Cloud network node metadata. | 
| PrismaCloud.Network.Connection.from | Number | Cloud network connection from node ID. | 
| PrismaCloud.Network.Connection.to | Number | Cloud network connection to node ID. | 
| PrismaCloud.Network.Connection.label | String | Cloud network connection label. | 
| PrismaCloud.Network.Connection.suspicious | Boolean | Whether the cloud network node is suspicious. | 
| PrismaCloud.Network.Connection.metadata | Unknown | Cloud network connection metadata. | 

#### Command example
```!prisma-cloud-network-search query="network from vpc.flow_record where cloud.account = 'AWS Prod' AND source.publicnetwork IN ( 'Suspicious IPs' ) AND bytes > 0 "```
#### Context Example
```json
{
    "PrismaCloud": {
        "Network": {
            "Connection": [
                {
                    "from": -963693921,
                    "label": "Web & 1 more",
                    "metadata": {
                        "account_id": [
                            "888888888888"
                        ],
                        "asset_role": [
                            "Suspicious IPs"
                        ],
                        "bytes_accepted": 598088,
                        "bytes_attempted": 360,
                        "bytes_rejected": 0,
                        "cloud_type": [
                            "aws"
                        ],
                        "connection_overview_table": [
                            {
                                "accepted": "yes",
                                "port": "Web (80)",
                                "traffic_volume": 565611
                            },
                            {
                                "accepted": "yes",
                                "port": "SSH (22)",
                                "traffic_volume": 32477
                            },
                            {
                                "accepted": "no",
                                "port": "Web (80)",
                                "traffic_volume": 360
                            }
                        ],
                        "countries": [
                            "N/A"
                        ],
                        "flow_class": [
                            "Web (80)",
                            "SSH (22)"
                        ],
                        "from_ip_addresses": [
                            "0.0.0.0"
                        ],
                        "isps": [
                            "N/A"
                        ],
                        "region_id": [
                            "N/A"
                        ],
                        "states": [
                            "N/A"
                        ],
                        "suspicious_ips": [
                            "35.180.1.1",
                            "172.31.34.235"
                        ],
                        "to_ip_addresses": [
                            "35.180.1.1",
                            "10.0.2.5"
                        ]
                    },
                    "suspicious": true,
                    "to": -1695489264
                }
            ],
            "Node": [
                {
                    "grouped": false,
                    "iconId": "web_server",
                    "id": -1695489264,
                    "ipAddr": "10.0.2.5",
                    "metadata": {
                        "account_id": [
                            "888888888888"
                        ],
                        "account_name": [
                            "AWS Prod"
                        ],
                        "asset_role": [
                            "VM Instance",
                            "SSH",
                            "Web Server"
                        ],
                        "cloud_type": [
                            "aws"
                        ],
                        "compliance_count": 0,
                        "guard_duty_host_count": 4,
                        "guard_duty_iam_count": 0,
                        "host_vulnerability_count": 0,
                        "initial": true,
                        "inspector_rba_count": 0,
                        "inspector_sbp_count": 0,
                        "instance_id": [
                            "i-0d"
                        ],
                        "ip_addresses": [
                            "10.0.2.5"
                        ],
                        "net_iface_id": [
                            "eni-08"
                        ],
                        "redlock_alert_count": 10,
                        "region_id": [
                            "us-west-1"
                        ],
                        "region_name": [
                            "AWS California"
                        ],
                        "resource_id": [
                            "i-00"
                        ],
                        "rrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
                        "secgroup_ids": [
                            "sg-0a"
                        ],
                        "security_groups": [
                            {
                                "id": "sg-0a",
                                "name": "WebServersg"
                            }
                        ],
                        "serverless_vulnerability_count": 0,
                        "tags": [
                            {
                                "name": "aws:cloudformation:stack-name",
                                "values": [
                                    "aaa"
                                ]
                            },
                            {
                                "name": "aws:cloudformation:stack-id",
                                "values": [
                                    "arn:aws:trail:us-west-1:888888888888:trail/control"
                                ]
                            },
                            {
                                "name": "aws:cloudformation:logical-id",
                                "values": [
                                    "WebServerInstance"
                                ]
                            },
                            {
                                "name": "Name",
                                "values": [
                                    "PANW-WebServer"
                                ]
                            }
                        ],
                        "vpc_id": [
                            "vpc-07"
                        ],
                        "vpc_name": [
                            {
                                "id": "vpc-07",
                                "name": "VPC-aaa"
                            }
                        ]
                    },
                    "name": "PANW-WebServer",
                    "suspicious": false,
                    "vulnerable": true
                },
                {
                    "grouped": true,
                    "iconId": "suspicious",
                    "id": -963693921,
                    "ipAddr": "0.0.0.0",
                    "metadata": {
                        "account_id": [
                            "888888888888"
                        ],
                        "account_name": [
                            "N/A"
                        ],
                        "asset_role": [
                            "Suspicious IPs"
                        ],
                        "bytes_accepted": 1368976,
                        "bytes_attempted": 2428,
                        "bytes_rejected": 0,
                        "cloud_type": [
                            "aws"
                        ],
                        "compliance_count": 0,
                        "countries": [
                            "N/A"
                        ],
                        "guard_duty_host_count": 0,
                        "guard_duty_iam_count": 0,
                        "host_vulnerability_count": 0,
                        "inspector_rba_count": 0,
                        "inspector_sbp_count": 0,
                        "instance_id": [
                            "N/A"
                        ],
                        "ip_addresses": [
                            "N/A"
                        ],
                        "isps": [
                            "N/A"
                        ],
                        "launched_on": [
                            "N/A"
                        ],
                        "net_iface_id": [
                            "N/A"
                        ],
                        "redlock_alert_count": 0,
                        "region_id": [
                            "N/A"
                        ],
                        "region_name": [
                            "N/A"
                        ],
                        "resource_id": [
                            "N/A"
                        ],
                        "secgroup_ids": [
                            "N/A"
                        ],
                        "secgroup_names": [
                            "N/A"
                        ],
                        "security_groups": [
                            "N/A"
                        ],
                        "serverless_vulnerability_count": 0,
                        "specificIps": [
                            "172.31.34.235",
                            "1.1.1.1"
                        ],
                        "states": [
                            "N/A"
                        ],
                        "tags": [
                            "N/A"
                        ],
                        "vpc_name": [
                            "N/A"
                        ]
                    },
                    "name": "Suspicious IPs",
                    "suspicious": false,
                    "vulnerable": false
                }
            ]
        }
    }
}
```

#### Human Readable Output

>## Network Details
>### Nodes:
>|Id|Name|Ip Addr|Grouped|Suspicious|Vulnerable|
>|---|---|---|---|---|---|
>| -1695489264 | PANW-WebServer | 10.0.2.5 | false | false | true |
>| -963693921 | Suspicious IPs | 0.0.0.0 | true | false | false |
>### Connections:
>|From|To|Label|Suspicious|
>|---|---|---|---|
>| -963693921 | -1695489264 | Web & 1 more | true |


### prisma-cloud-error-file-list

***
Deprecated, use the ***prisma-cloud-code-issues-list*** command instead.



### prisma-cloud-trigger-scan

***
Trigger asynchronous scan of all resources to refresh the current state at Prisma Cloud Code Security. In order to use this command, the "Code Security" module needs to be enabled and accessible in the Prisma Cloud UI.

#### Base Command

`prisma-cloud-trigger-scan`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
#### Command example
```!prisma-cloud-trigger-scan```
#### Human Readable Output

>### Trigger Scan Results:
>|Is Executed|Message|
>|---|---|
>| false | Executing a new scan has failed - a scheduled scan is already in progress. |


### prisma-cloud-resource-get

***
Get resource details.

#### Base Command

`prisma-cloud-resource-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rrn | Restricted Resource Name of the resource to get details about. Can be retrieved by running a command that has that RRN. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.Resource.rrn | String | Prisma Cloud restricted resource name. | 
| PrismaCloud.Resource.id | String | Prisma Cloud resource ID. | 
| PrismaCloud.Resource.name | String | Resource name. | 
| PrismaCloud.Resource.url | String | Resource URL. | 
| PrismaCloud.Resource.accountId | String | Cloud account ID. | 
| PrismaCloud.Resource.accountName | String | Cloud account name. | 
| PrismaCloud.Resource.cloudType | String | Cloud type. | 
| PrismaCloud.Resource.regionId | String | Cloud region ID. | 
| PrismaCloud.Resource.regionName | String | Cloud region Name. | 
| PrismaCloud.Resource.service | String | Cloud service. | 
| PrismaCloud.Resource.resourceType | String | Cloud resource type. | 
| PrismaCloud.Resource.insertTs | Date | Insert timestamp. | 
| PrismaCloud.Resource.deleted | Boolean | Whether the resource was deleted. | 
| PrismaCloud.Resource.vpcId | String | VPC ID. | 
| PrismaCloud.Resource.vpcName | String | VPC name. | 
| PrismaCloud.Resource.tags | Unknown | Prisma Cloud resource tags. | 
| PrismaCloud.Resource.riskGrade | String | Risk grade. | 
| PrismaCloud.Resource.hasNetwork | Boolean | Whether the resource has a network. | 
| PrismaCloud.Resource.hasExternalFinding | Boolean | Whether the resource has an external finding. | 
| PrismaCloud.Resource.hasExternalIntegration | Boolean | Whether the resource has an external integration. | 
| PrismaCloud.Resource.allowDrillDown | Boolean | Whether to allow drill down. | 
| PrismaCloud.Resource.hasExtFindingRiskFactors | Boolean | Whether the resource has external finding risk factors. | 
| PrismaCloud.Resource.data | Unknown | Prisma Cloud resource specific data. | 

#### Command example
```!prisma-cloud-resource-get rrn=rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25```
#### Context Example
```json
{
    "PrismaCloud": {
        "Resource": {
            "accountId": "111111111111",
            "accountName": "AAAAAAA",
            "allowDrillDown": true,
            "cloudType": "aws",
            "data": {
                "attributes": [
                    {
                        "attributeName": "restore",
                        "attributeValues": []
                    }
                ],
                "snapshot": {
                    "allocatedStorage": 20,
                    "availabilityZone": "us-east-1a",
                    "dbiResourceId": "db-S",
                    "dbinstanceIdentifier": "aaaaaaaaaaaaaa",
                    "dbsnapshotArn": "arn:aws:trail:us-west-1:888888888888:trail/control",
                    "dbsnapshotIdentifier": "rds:aaaaaaaaaaaaaa-2023-01-29-09-25",
                    "encrypted": false,
                    "engine": "postgres",
                    "engineVersion": "13.7",
                    "iamdatabaseAuthenticationEnabled": false,
                    "instanceCreateTime": "2022-07-22T18:35:54.809Z",
                    "licenseModel": "postgresql-license",
                    "masterUsername": "master",
                    "optionGroupName": "default:postgres-13",
                    "originalSnapshotCreateTime": "2023-01-29T09:25:08.698Z",
                    "percentProgress": 100,
                    "port": 5432,
                    "processorFeatures": [],
                    "snapshotCreateTime": "2023-01-29T09:25:08.698Z",
                    "snapshotTarget": "region",
                    "snapshotType": "automated",
                    "status": "available",
                    "storageThroughput": 0,
                    "storageType": "standard",
                    "tagList": [],
                    "vpcId": "vpc-0f"
                },
                "tags": []
            },
            "deleted": true,
            "hasExtFindingRiskFactors": false,
            "hasExternalFinding": false,
            "hasExternalIntegration": false,
            "hasNetwork": false,
            "id": "rds:aaaaaaaaaaaaaa-2023-01-29-09-25",
            "insertTs": "2023-01-29T09:35:27Z",
            "name": "rds:aaaaaaaaaaaaaa-2023-01-29-09-25",
            "regionId": "us-east-1",
            "regionName": "AWS Virginia",
            "resourceConfigJsonAvailable": false,
            "resourceType": "Managed Database Snapshot",
            "riskGrade": "A",
            "rrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
            "service": "Amazon RDS",
            "tags": {
                "": ""
            },
            "url": "https://some-url?region=us-east-1#db-snapshots:id=rds:aaaaaaaaaaaaaa-2023-01-29-09-25",
            "vpcId": "vpc-0f",
            "vpcName": "ServerlessVPC"
        }
    }
}
```

#### Human Readable Output

>### Resource Details:
>|Rrn|Id|Name|Url|Account Id|Account Name|Cloud Type|Region Id|Region Name|Service|Resource Type|Insert Ts|Deleted|Vpc Id|Vpc Name|Tags|Risk Grade|Has Network|Has External Finding|Has External Integration|Allow Drill Down|Has Ext Finding Risk Factors|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25 | rds:aaaaaaaaaaaaaa-2023-01-29-09-25 | rds:aaaaaaaaaaaaaa-2023-01-29-09-25 | [https://some_url?region=us-east-1#db-snapshots:id=rds:aaaaaaaaaaaaaa-2023-01-29-09-25](https://some_url/rds/home?region=us-east-1#db-snapshots:id=rds:aaaaaaaaaaaaaa-2023-01-29-09-25) | 111111111111 | AAAAAAA | aws | us-east-1 | AWS Virginia | Amazon RDS | Managed Database Snapshot | 2023-01-29T09:35:27Z | true | vpc-0f | ServerlessVPC | :  | A | false | false | false | true | false |

### prisma-cloud-resource-list
***
Returns all the resource lists. Maps to the Resource Lists under Settings > Resource Lists in the Console UI.


#### Base Command

`prisma-cloud-resource-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | The resource list type. | Optional | 
| limit | Maximum number of entries to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.ResourceList.id | String | Prisma Cloud resource list ID. | 
| PrismaCloud.ResourceList.name | String | Resource list name. | 
| PrismaCloud.ResourceList.resourceListType | String | Resource list type. | 
| PrismaCloud.ResourceList.description | String | Resource list description. | 
| PrismaCloud.ResourceList.lastModifiedBy | String | Resource list last modified user. | 
| PrismaCloud.ResourceList.lastModifiedTs | Date | Resource list last modified time. | 
| PrismaCloud.ResourceList.members | Unknown | Resource list members. | 

#### Command example
```!prisma-cloud-resource-list limit=3```
#### Context Example
```json
{
    "PrismaCloud": {
        "ResourceList": [
            {
                "description": null,
                "id": "aa11bb22",
                "lastModifiedBy": "admin@paloaltonetworks.com",
                "lastModifiedTs": "2021-09-20T16:23:15Z",
                "members": [
                    {
                        "demo": "lab"
                    },
                    {
                        "dev": "prisma"
                    },
                    {
                        "env": "lab"
                    }
                ],
                "name": "First",
                "resourceListType": "TAG"
            },
            {
                "description": null,
                "id": "aa22bb11",
                "lastModifiedBy": "admin2@paloaltonetworks.com",
                "lastModifiedTs": "2023-03-10T04:54:34Z",
                "members": [
                    {
                    }
                ],
                "name": "other",
                "resourceListType": "COMPUTE_ACCESS_GROUP"
            },
            {
                "description": null,
                "id": "a3b4",
                "lastModifiedBy": "test@paloaltonetworks.com",
                "lastModifiedTs": "2023-07-10T22:27:55Z",
                "members": [
                    {
                        "labels": [
                            "*"
                        ],
                        "namespaces": [
                            "*"
                        ]
                    }
                ],
                "name": "panw",
                "resourceListType": "COMPUTE_ACCESS_GROUP"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 3 of 6 results:
>### Resources Details:
>|Name|Id|Type|Last Modified By|
>|---|---|---|---|
>| First | aa11bb22 | TAG | admin@paloaltonetworks.com |
>| other | aa22bb11 | COMPUTE_ACCESS_GROUP | admin2@paloaltonetworks.com |
>| panw | a3b4 | COMPUTE_ACCESS_GROUP | test@paloaltonetworks.com |

### prisma-cloud-user-roles-list
***
Retrieves user roles. Maps to Settings > Access Control > Roles in the Console UI.


#### Base Command

`prisma-cloud-user-roles-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_id | The role id to get details of. | Optional | 
| limit | Maximum number of entries to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.UserRoles.id | String | Prisma Cloud user roles ID. | 
| PrismaCloud.UserRoles.name | String | User roles name. | 
| PrismaCloud.UserRoles.resourceListIds | Unknown | User roles resource list IDs. | 
| PrismaCloud.UserRoles.description | String | User roles description. | 
| PrismaCloud.UserRoles.lastModifiedBy | String | User roles last modified user. | 
| PrismaCloud.UserRoles.lastModifiedTs | Date | User roles last modified time. | 
| PrismaCloud.UserRoles.associatedUsers | Unknown | User roles associated users. | 
| PrismaCloud.UserRoles.restrictDismissalAccess | Boolean | Whether dismissal access is restricted for the user role. | 
| PrismaCloud.UserRoles.roleType | String | User roles role type. | 
| PrismaCloud.UserRoles.additionalAttributes | Unknown | User roles additional attributes. | 
| PrismaCloud.UserRoles.codeRepositoryIds | Unknown | User roles code repository IDs. | 
| PrismaCloud.UserRoles.accountGroupIds | Unknown | User roles account group IDs. | 
| PrismaCloud.UserRoles.resourceLists | Unknown | User roles resource lists. | 
| PrismaCloud.UserRoles.permissionGroup | Unknown | User roles permission group. | 
| PrismaCloud.UserRoles.codeRepositories | Unknown | User roles code repositories. | 
| PrismaCloud.UserRoles.accountGroups | Unknown | User roles account groups. | 

#### Command example
```!prisma-cloud-user-roles-list limit=3```
#### Context Example
```json
{
    "PrismaCloud": {
        "UserRoles": [
            {
                "accountGroupIds": [],
                "accountGroups": [],
                "additionalAttributes": {
                    "hasDefenderPermissions": false,
                    "onlyAllowCIAccess": false,
                    "onlyAllowComputeAccess": false,
                    "onlyAllowReadAccess": false
                },
                "associatedUsers": [
                    "lab",
                    "demo"
                ],
                "codeRepositories": [],
                "codeRepositoryIds": [],
                "description": "",
                "id": "a2b2",
                "lastModifiedBy": "test@paloaltonetworks.com",
                "lastModifiedTs": "2023-08-02T17:47:07Z",
                "name": "dev-test",
                "permissionGroup": null,
                "resourceListIds": [],
                "resourceLists": [],
                "restrictDismissalAccess": true,
                "roleType": "Developer"
            },
            {
                "accountGroupIds": [],
                "accountGroups": [],
                "additionalAttributes": {
                    "hasDefenderPermissions": false,
                    "onlyAllowCIAccess": false,
                    "onlyAllowComputeAccess": false,
                    "onlyAllowReadAccess": false
                },
                "associatedUsers": [
                    "test"
                ],
                "codeRepositories": [],
                "codeRepositoryIds": [],
                "description": "",
                "id": "a3b3",
                "lastModifiedBy": "admin@paloaltonetworks.com",
                "lastModifiedTs": "2023-07-21T15:27:04Z",
                "name": "Custom Read Only",
                "permissionGroup": null,
                "resourceListIds": [],
                "resourceLists": [],
                "restrictDismissalAccess": false,
                "roleType": "Custom Read Only"
            },
            {
                "accountGroupIds": [
                    "aaa111",
                    "bbb222"
                ],
                "accountGroups": [
                    {
                        "id": "aaa111",
                        "name": "group1"
                    },
                    {
                        "id": "bbb222",
                        "name": "group2"
                    }
                ],
                "additionalAttributes": {
                    "hasDefenderPermissions": false,
                    "onlyAllowCIAccess": false,
                    "onlyAllowComputeAccess": false,
                    "onlyAllowReadAccess": true
                },
                "associatedUsers": [
                    "user1",
                    "user2"
                ],
                "codeRepositories": [
                    {
                        "id": "a3c3",
                        "name": "demo"
                    }
                ],
                "codeRepositoryIds": [
                    "a3c3"
                ],
                "description": "",
                "id": "a4b4",
                "lastModifiedBy": "test@paloaltonetworks.com",
                "lastModifiedTs": "2023-07-18T19:27:59Z",
                "name": "Read Only",
                "permissionGroup": null,
                "resourceListIds": [],
                "resourceLists": [],
                "restrictDismissalAccess": true,
                "roleType": "Account Group Read Only"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 3 of 14 results:
>### User Roles Details:
>|Name|Id|Role Type|
>|---|---|---|
>| dev-test | a2b2 | Developer |
>| Custom Read Only | a3b3 | Custom Read Only |
>| Read Only | a4b4 | Account Group Read Only |

### prisma-cloud-users-list
***
Lists all users and service accounts for your tenant. Maps to Settings > Access Control > Users in the Console UI.


#### Base Command

`prisma-cloud-users-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of entries to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Possible values are: true, false. | Optional | 
| usernames | Usernames to return only users associated with. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.Users.email | String | Prisma Cloud user email. | 
| PrismaCloud.Users.firstName | String | User first name. | 
| PrismaCloud.Users.lastName | String | User last name. | 
| PrismaCloud.Users.timeZone | String | User time zone. | 
| PrismaCloud.Users.enabled | Boolean | User enabled. | 
| PrismaCloud.Users.lastModifiedBy | String | User last modified user. | 
| PrismaCloud.Users.lastModifiedTs | Date | User last modified time. | 
| PrismaCloud.Users.lastLoginTs | Date | User last login time. | 
| PrismaCloud.Users.displayName | String | User display name. | 
| PrismaCloud.Users.ssoBypassAllowed | Boolean | Whether SSO bypass is allowed for the user role. | 
| PrismaCloud.Users.accessKeysAllowed | Boolean | Whether access keys are allowed for the user role. | 
| PrismaCloud.Users.defaultRoleId | String | User default role ID. | 
| PrismaCloud.Users.roleIds | Unknown | User role IDs. | 
| PrismaCloud.Users.roles | Unknown | User roles. | 
| PrismaCloud.Users.username | String | User username. | 
| PrismaCloud.Users.type | String | User type. | 
| PrismaCloud.Users.enableKeyExpiration | Boolean | Whether key expiration is enabled for the user role. | 
| PrismaCloud.Users.accessKeysCount | Number | User access keys count. | 

#### Command example
```!prisma-cloud-users-list limit=2```
#### Context Example
```json
{
    "PrismaCloud": {
        "Users": [
            {
                "accessKeysAllowed": false,
                "accessKeysCount": 0,
                "defaultRoleId": "a4b4",
                "displayName": "User Test",
                "email": "test@paloaltonetworks.com",
                "enableKeyExpiration": false,
                "enabled": true,
                "firstName": "User",
                "lastLoginTs": "1969-12-31T23:59:59Z",
                "lastModifiedBy": "admin@paloaltonetworks.com",
                "lastModifiedTs": "2020-01-21T22:35:36Z",
                "lastName": "Test",
                "roleIds": [
                    "a4b4"
                ],
                "roles": [
                    {
                        "id": "a4b4",
                        "name": "Read Only",
                        "onlyAllowCIAccess": false,
                        "onlyAllowComputeAccess": false,
                        "onlyAllowReadAccess": true,
                        "type": "Account Group Read Only"
                    }
                ],
                "roles names": [
                    "Read Only"
                ],
                "ssoBypassAllowed": false,
                "timeZone": "America/New_York",
                "type": "USER_ACCOUNT",
                "username": "test@paloaltonetworks.com"
            },
            {
                "accessKeysAllowed": false,
                "accessKeysCount": 0,
                "defaultRoleId": "a4b4",
                "displayName": "User Other",
                "email": "other@paloaltonetworks.com",
                "enableKeyExpiration": false,
                "enabled": true,
                "firstName": "User",
                "lastLoginTs": "2023-08-29T14:04:17Z",
                "lastModifiedBy": "USER-ADD",
                "lastModifiedTs": "2023-08-29T13:45:06Z",
                "lastName": "Other",
                "roleIds": [
                    "a4b4"
                ],
                "roles": [
                    {
                        "id": "a4b4",
                        "name": "Read Only",
                        "onlyAllowCIAccess": false,
                        "onlyAllowComputeAccess": false,
                        "onlyAllowReadAccess": true,
                        "type": "Account Group Read Only"
                    }
                ],
                "roles names": [
                    "Read Only"
                ],
                "ssoBypassAllowed": false,
                "timeZone": "America/New_York",
                "type": "USER_ACCOUNT",
                "username": "other@paloaltonetworks.com"
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 2 of 200 results:
>### Users Details:
>|Display Name|Email|Enabled|Username|Type|Roles Names|
>|---|---|---|---|---|---|
>| User Test | test@paloaltonetworks.com | true | test@paloaltonetworks.com | USER_ACCOUNT | Read Only |
>| User Other | other@paloaltonetworks.com | true | other@paloaltonetworks.com | USER_ACCOUNT | Read Only |

### prisma-cloud-account-list

***
List accounts.

#### Base Command

`prisma-cloud-account-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| exclude_account_group_details | Whether to exclude account group details. Possible values are: true, false. Default is false. | Optional | 
| limit | Maximum number of entries to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.Account.name | String | Account name. | 
| PrismaCloud.Account.cloudType | String | Account cloud type. | 
| PrismaCloud.Account.accountType | String | Account type. | 
| PrismaCloud.Account.enabled | Boolean | Whether the account is enabled. | 
| PrismaCloud.Account.lastModifiedTs | Date | Account last modified time. | 
| PrismaCloud.Account.storageScanEnabled | Boolean | Whether account storage scan is enabled. | 
| PrismaCloud.Account.protectionMode | String | Account protection mode. | 
| PrismaCloud.Account.ingestionMode | Number | Account ingestion mode. | 
| PrismaCloud.Account.deploymentType | String | Account deployment type. | 
| PrismaCloud.Account.groupIds | Unknown | Account group IDs. | 
| PrismaCloud.Account.groups | Unknown | Account groups. | 
| PrismaCloud.Account.status | String | Account status. | 
| PrismaCloud.Account.numberOfChildAccounts | Number | The number of child accounts. | 
| PrismaCloud.Account.accountId | String | Account ID. | 
| PrismaCloud.Account.addedOn | Date | Account added on time. | 

#### Command example
```!prisma-cloud-account-list limit=1```
#### Context Example
```json
{
    "PrismaCloud": {
        "Account": [
            {
                "accountId": "777777777777",
                "accountType": "organization",
                "addedOn": "2022-10-06T04:06:41Z",
                "cloudAccountOwner": "mail1@gmail.com",
                "cloudAccountOwnerCount": 1,
                "cloudType": "aws",
                "deploymentType": "aws",
                "enabled": true,
                "groupIds": [
                    "group2"
                ],
                "groups": [
                    {
                        "id": "group2",
                        "name": "Adi"
                    }
                ],
                "ingestionMode": 7,
                "lastModifiedBy": "example@example.com",
                "lastModifiedTs": "2022-10-06T12:48:42Z",
                "name": "aws-Adi-train",
                "numberOfChildAccounts": 4,
                "protectionMode": "MONITOR_AND_PROTECT",
                "status": "warning",
                "storageScanEnabled": false
            }
        ]
    }
}
```

#### Human Readable Output

>Showing 1 of 19 results:
>### Accounts Details:
>|Account Id|Name|Cloud Type|Account Type|Enabled|Added On|Last Modified Ts|Last Modified By|Storage Scan Enabled|Protection Mode|Ingestion Mode|Deployment Type|Status|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 777777777777 | aws-Adi-train | aws | organization | true | 2022-10-06T04:06:41Z | 2022-10-06T12:48:42Z | example@example.com | false | MONITOR_AND_PROTECT | 7 | aws | warning |


### prisma-cloud-account-status-get

***
Get the statuses of the provided accounts.

#### Base Command

`prisma-cloud-account-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | A comma-separated list of accound IDs. To get account IDs, run the "prisma-cloud-account-list" command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.Account.accountId | String | Account ID. | 
| PrismaCloud.Account.name | String | Account name. | 
| PrismaCloud.Account.status | String | Account status. | 
| PrismaCloud.Account.message | String | Account message. | 
| PrismaCloud.Account.remediation | String | Account remediation action. | 

#### Command example
```!prisma-cloud-account-status-get account_ids=111111111111```
#### Context Example
```json
{
    "PrismaCloud": {
        "Account": {
            "accountId": "111111111111",
            "message": "",
            "name": "Config",
            "remediation": "",
            "status": "ok",
            "subComponents": []
        }
    }
}
```

#### Human Readable Output

>### Accounts Status Details:
>|Account Id|Name|Status|
>|---|---|---|
>| 111111111111 | Config | ok |


### prisma-cloud-account-owner-list

***
Get the owners of the provided accounts.

#### Base Command

`prisma-cloud-account-owner-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | A comma-separated list of account IDs. To get account IDs, run the "prisma-cloud-account-list" command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.Account.accountId | String | Account ID. | 
| PrismaCloud.Account.emails | Unknown | Account owner emails. | 

#### Command example
```!prisma-cloud-account-owner-list account_ids=888888888888888888888888888888888888,111111111111```
#### Context Example
```json
{
    "PrismaCloud": {
        "Account": [
            {
                "accountId": "888888888888888888888888888888888888",
                "emails": [
                    "name@company.com"
                ]
            },
            {
                "accountId": "111111111111",
                "emails": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Accounts Owner Details:
>|Account Id|Emails|
>|---|---|
>| 888888888888888888888888888888888888 | name@company.com |
>| 111111111111 |  |


### prisma-cloud-host-finding-list

***
Get resource host finding list.

#### Base Command

`prisma-cloud-host-finding-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rrn | Restricted Resource Name of the resource to get host finding of. Can be retrieved by running a command that has that RRN. | Required | 
| finding_types | Comma separated list of finding types to look for. Available options are: guard_duty_host, guard_duty_iam, inspector_sbp, compliance_cis, host_vulnerability_cve. When left empty, will return all options. | Optional | 
| risk_factors | Comma separated list of risk factors to look for. Available options are: CRITICAL_SEVERITY, HIGH_SEVERITY, MEDIUM_SEVERITY, HAS_FIX, REMOTE_EXECUTION, DOS, RECENT_VULNERABILITY, EXPLOIT_EXISTS, ATTACK_COMPLEXITY_LOW, ATTACK_VECTOR_NETWORK, REACHABLE_FROM_THE_INTERNET, LISTENING_PORTS, CONTAINER_IS_RUNNING_AS_ROOT, NO_MANDATORY_SECURITY_PROFILE_APPLIED, RUNNING_AS_PRIVILEGED_CONTAINER, PACKAGE_IN_USE. When left empty, will return all options. | Optional | 
| limit | Maximum number of entries to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.HostFinding.accountId | String | Host finding account ID. | 
| PrismaCloud.HostFinding.regionId | String | Host finding region ID. | 
| PrismaCloud.HostFinding.findingId | String | Host finding ID. | 
| PrismaCloud.HostFinding.type | String | Host finding type. | 
| PrismaCloud.HostFinding.source | String | Host finding source. | 
| PrismaCloud.HostFinding.severity | String | Host finding severity. | 
| PrismaCloud.HostFinding.status | String | Host finding status. | 
| PrismaCloud.HostFinding.createdOn | Date | The date on which the host finding was created. | 
| PrismaCloud.HostFinding.updatedOn | Date | The date on which the host finding was updated. | 
| PrismaCloud.HostFinding.normalizedNames | Unknown | Host finding normalized names. | 
| PrismaCloud.HostFinding.scanId | String | Host finding scan ID. | 
| PrismaCloud.HostFinding.resourceCloudId | String | Host finding resource cloud ID. | 
| PrismaCloud.HostFinding.sourceData.accountId | String | Host finding source data account ID. | 
| PrismaCloud.HostFinding.sourceData.arn | String | Host finding source data ARN. | 
| PrismaCloud.HostFinding.title | String | Host finding title. | 
| PrismaCloud.HostFinding.description | String | Host finding description. | 
| PrismaCloud.HostFinding.resourceUrl | String | Host finding resource URL. | 
| PrismaCloud.HostFinding.rlUpdatedOn | Date | The date on which the RL was updated. | 
| PrismaCloud.HostFinding.externalFindingId | String | External finding ID. | 
| PrismaCloud.HostFinding.sourceData | Unknown | Host finding source data. | 
| PrismaCloud.HostFinding.score | String | Host finding score. | 
| PrismaCloud.HostFinding.count | Number | The number of host findings. | 

#### Command example
```!prisma-cloud-host-finding-list rrn=rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25 finding_types=guard_duty_host,guard_duty_iam limit=2```
#### Context Example
```json
{
    "PrismaCloud": {
        "HostFinding": {
            "accountId": "555555555555",
            "count": "5",
            "createdOn": "2023-01-03T16:13:25Z",
            "description": "35.180.1.1 is performing SSH brute force attacks against i-44444444444444444. Brute force attacks are used to gain unauthorized access to your instance by guessing the SSH password.",
            "externalFindingId": 999999,
            "findingId": "findingid3",
            "normalizedNames": [
                "UnauthorizedAccess:EC2/SSHBruteForce"
            ],
            "regionId": "us-east-1",
            "resourceCloudId": "i-44444444444444444",
            "resourceUrl": "https://some-url?#/findings?search=id%3D66666666666666666666666666666666",
            "rlUpdatedOn": "2023-02-16T16:27:26Z",
            "scanId": "scan-id-5",
            "score": "N/A",
            "severity": "low",
            "source": "guardduty",
            "sourceData": {
                "accountId": "555555555555",
                "arn": "arn:aws:trail:us-west-1:888888888888:trail/control",
                "createdAt": "2023-01-03T16:13:25.421Z",
                "description": "35.180.1.1 is performing SSH brute force attacks against i-44444444444444444. Brute force attacks are used to gain unauthorized access to your instance by guessing the SSH password.",
                "id": "66666666666666666666666666666666",
                "partition": "aws",
                "region": "us-east-1",
                "resource": {
                    "instanceDetails": {
                        "availabilityZone": "us-east-1a",
                        "iamInstanceProfile": {
                            "arn": "arn:aws:trail:us-west-1:888888888888:trail/control",
                            "id": "A2"
                        },
                        "imageDescription": "Amazon Linux AMI 2.0.20222202 x86_64 ECS HVM GP2",
                        "imageId": "ami-2",
                        "instanceId": "i-44444444444444444",
                        "instanceState": "running",
                        "instanceType": "t2.xlarge",
                        "launchTime": "2022-12-13T01:29:18.000Z",
                        "networkInterfaces": [
                            {
                                "ipv6Addresses": [],
                                "networkInterfaceId": "eni-1",
                                "privateDnsName": "ip-1-1-1-1.ec2.internal",
                                "privateIpAddress": "1.1.1.1",
                                "privateIpAddresses": [
                                    {
                                        "privateDnsName": "ip-1-1-1-1.ec2.internal",
                                        "privateIpAddress": "1.1.1.1"
                                    }
                                ],
                                "publicDnsName": "ec2-5.compute-1.amazonaws.com",
                                "publicIp": "1.1.1.1",
                                "sgs": [
                                    {
                                        "groupId": "sg-000",
                                        "groupName": "security-group"
                                    }
                                ],
                                "subnetId": "subnet-0",
                                "vpcId": "vpc-01"
                            }
                        ],
                        "productCodes": [],
                        "tags": [
                            {
                                "key": "aws:autoscaling:groupName",
                                "value": "pc-infra-autoscaling"
                            }
                        ]
                    },
                    "resourceType": "Instance"
                },
                "schemaVersion": "2.0",
                "service": {
                    "action": {
                        "actionType": "NETWORK_CONNECTION",
                        "networkConnectionAction": {
                            "blocked": false,
                            "connectionDirection": "INBOUND",
                            "localIpDetails": {
                                "ipAddressV4": "1.1.1.1"
                            },
                            "localPortDetails": {
                                "port": 22,
                                "portName": "SSH"
                            },
                            "protocol": "TCP",
                            "remoteIpDetails": {
                                "city": {
                                    "cityName": "George Town"
                                },
                                "country": {
                                    "countryName": "Malaysia"
                                },
                                "geoLocation": {
                                    "lat": 5.4244,
                                    "lon": 100.333
                                },
                                "ipAddressV4": "35.180.1.1",
                                "organization": {
                                    "asn": "9999",
                                    "asnOrg": "TIME",
                                    "isp": "TIME",
                                    "org": "TIME"
                                }
                            },
                            "remotePortDetails": {
                                "port": 33333,
                                "portName": "Unknown"
                            }
                        }
                    },
                    "additionalInfo": {
                        "type": "default",
                        "value": "{}"
                    },
                    "archived": false,
                    "count": 5,
                    "detectorId": "scan-id-5",
                    "eventFirstSeen": "2023-01-03T15:56:55.000Z",
                    "eventLastSeen": "2023-02-16T15:53:32.000Z",
                    "resourceRole": "TARGET",
                    "serviceName": "guardduty"
                },
                "severity": 2,
                "title": "35.180.1.1 is performing SSH brute force attacks against i-44444444444444444.",
                "type": "UnauthorizedAccess:EC2/SSHBruteForce",
                "updatedAt": "2023-02-16T16:01:36.608Z"
            },
            "status": "open",
            "title": "35.180.1.1 is performing SSH brute force attacks against i-44444444444444444.",
            "type": "guard_duty_host",
            "updatedOn": "2023-02-16T16:01:36Z"
        }
    }
}
```

#### Human Readable Output

>Showing 1 of 1 results:
>### Host Finding Details:
>|Account Id|Region Id|Finding Id|Type|Source|Severity|Status|Created On|Updated On|Normalized Names|Scan Id|Resource Cloud Id|Source Data Account ID|ARN|Title|Description|Resource Url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 555555555555 | us-east-1 | 66666666666666666666666666666666 | guard_duty_host | guardduty | low | open | 2023-01-03T16:13:25Z | 2023-02-16T16:01:36Z | UnauthorizedAccess:EC2/SSHBruteForce | scan-id-5 | i-44444444444444444 | 555555555555 | arn:aws:trail:us-west-1:888888888888:trail/control | 35.180.1.1 is performing SSH brute force attacks against i-44444444444444444. | 35.180.1.1 is performing SSH brute force attacks against i-44444444444444444. Brute force attacks are used to gain unauthorized access to your instance by guessing the SSH password. | [https://some_url?#/findings?search=id%3D66666666666666666666666666666666](https://some_url?#/findings?search=id%3D66666666666666666666666666666666) |


### prisma-cloud-permission-list

***
Get permission list. You must provide either "query" or "next_token".

#### Base Command

`prisma-cloud-permission-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID to look for. Must be provided with the "query" argument. | Optional | 
| query | IAM query to run in Prisma Cloud config API using RQL language. For more information see: https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-rql-reference/rql-reference/iam-query. | Optional | 
| limit | Maximum number of entries to return. Default is 50. | Optional | 
| next_token | Token of the next page to retrive. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.PermissionPageToken.nextPageToken | String | Next page token. | 
| PrismaCloud.Permission.id | String | Permission ID. | 
| PrismaCloud.Permission.sourceCloudType | String | Permission source cloud type. | 
| PrismaCloud.Permission.sourceCloudAccount | String | Permission source cloud account. | 
| PrismaCloud.Permission.sourceResourceId | String | Permission source resource ID. | 
| PrismaCloud.Permission.destCloudType | String | Permission destination cloud type. | 
| PrismaCloud.Permission.destCloudServiceName | String | Permission destination cloud service name. | 
| PrismaCloud.Permission.destResourceType | String | Permission destination resource type. | 
| PrismaCloud.Permission.effectiveActionName | String | Permission effective action name. | 
| PrismaCloud.Permission.grantedByCloudType | String | Permission granted by cloud type. | 
| PrismaCloud.Permission.grantedByCloudPolicyId | String | Permission granted by cloud policy ID. | 
| PrismaCloud.Permission.grantedByCloudPolicyName | String | Permission granted by cloud policy name. | 
| PrismaCloud.Permission.grantedByCloudPolicyType | String | Permission granted by cloud policy type. | 
| PrismaCloud.Permission.grantedByCloudPolicyRrn | String | Permission granted by cloud policy restricted resource name. | 
| PrismaCloud.Permission.grantedByCloudEntityId | String | Permission granted by cloud entity ID. | 
| PrismaCloud.Permission.grantedByCloudEntityName | String | Permission granted by cloud entity name. | 
| PrismaCloud.Permission.grantedByCloudEntityRrn | String | Permission granted by cloud entity restricted resource name. | 
| PrismaCloud.Permission.sourcePublic | Boolean | Whether the permission source is public. | 
| PrismaCloud.Permission.sourceCloudRegion | String | Permission source cloud region. | 
| PrismaCloud.Permission.sourceCloudServiceName | String | Permission source cloud service name. | 
| PrismaCloud.Permission.sourceResourceName | String | Permission source resource name. | 
| PrismaCloud.Permission.sourceResourceType | String | Permission source resource type. | 
| PrismaCloud.Permission.sourceIdpService | String | Permission source IDP service. | 
| PrismaCloud.Permission.sourceIdpDomain | String | Permission source IDP domain. | 
| PrismaCloud.Permission.sourceIdpEmail | String | Permission source IDP email. | 
| PrismaCloud.Permission.sourceIdpUsername | String | Permission source IDP username. | 
| PrismaCloud.Permission.sourceIdpGroup | String | Permission source IDP group. | 
| PrismaCloud.Permission.sourceIdpRrn | String | Permission source IDP restricted resource name. | 
| PrismaCloud.Permission.sourceCloudResourceRrn | String | Permission source cloud resource restricted resource name. | 
| PrismaCloud.Permission.destCloudAccount | String | Permission destination cloud account. | 
| PrismaCloud.Permission.destCloudRegion | String | Permission destination cloud region. | 
| PrismaCloud.Permission.destResourceName | String | Permission destination resource name. | 
| PrismaCloud.Permission.destResourceId | String | Permission destination resource ID. | 
| PrismaCloud.Permission.destCloudResourceRrn | String | Permission destination cloud resource restricted resource name. | 
| PrismaCloud.Permission.grantedByCloudEntityType | String | Permission granted by cloud entity type. | 
| PrismaCloud.Permission.accessedResourcesCount | String | Permission accessed resources count. | 
| PrismaCloud.Permission.lastAccessDate | String | Permission last access date. | 
| PrismaCloud.Permission.lastAccessStatus | String | Permission last access status. | 
| PrismaCloud.Permission.isWildCardDestCloudResourceName | Boolean | Whether the destination cloud resource name is a wildcard. | 
| PrismaCloud.Permission.exceptions | Unknown | Permission exceptions. | 
| PrismaCloud.Permission.grantedByLevelType | String | Permission granted by level type. | 
| PrismaCloud.Permission.grantedByLevelId | String | Permission granted by level ID. | 
| PrismaCloud.Permission.grantedByLevelName | String | Permission granted by level name. | 
| PrismaCloud.Permission.grantedByLevelRrn | String | Permission granted by level restricted resource name. | 

#### Command example
```!prisma-cloud-permission-list query="config from iam where source.cloud.service.name = 'EC2'" limit=2```
#### Context Example
```json
{
    "PrismaCloud": {
        "Permission": [
            {
                "accessedResourcesCount": null,
                "destCloudAccount": "AWS-JLo",
                "destCloudRegion": "*",
                "destCloudResourceRrn": null,
                "destCloudServiceName": "ec2",
                "destCloudType": "AWS",
                "destResourceId": "*",
                "destResourceName": "*",
                "destResourceType": "instance",
                "effectiveActionName": "ssm:UpdateInstanceInformation",
                "exceptions": [
                    {
                        "messageCode": "CLOUD_EVENT_NOT_SUPPORTED"
                    },
                    {
                        "messageCode": "AWS_ROOT_ACCOUNT_IS_NOT_ONBOARDED"
                    }
                ],
                "grantedByCloudEntityId": "arn:aws:trail:us-west-1:888888888888:trail/control",
                "grantedByCloudEntityName": "service-role/AWSCloud9SSMAccessRole",
                "grantedByCloudEntityRrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
                "grantedByCloudEntityType": "role",
                "grantedByCloudPolicyId": "arn:aws:arn:aws:trail:us-west-1:888888888888:trail/control",
                "grantedByCloudPolicyName": "AWSCloud9SSMInstanceProfile",
                "grantedByCloudPolicyRrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
                "grantedByCloudPolicyType": "AWS Managed Policy",
                "grantedByCloudType": "AWS",
                "grantedByLevelId": null,
                "grantedByLevelName": null,
                "grantedByLevelRrn": null,
                "grantedByLevelType": "",
                "id": "jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj",
                "isWildCardDestCloudResourceName": true,
                "lastAccessDate": null,
                "lastAccessStatus": "NOT_AVAILABLE",
                "sourceCloudAccount": "AWS-JLo",
                "sourceCloudRegion": "AWS Oregon",
                "sourceCloudResourceRrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
                "sourceCloudServiceName": "ec2",
                "sourceCloudType": "AWS",
                "sourceIdpDomain": null,
                "sourceIdpEmail": null,
                "sourceIdpGroup": null,
                "sourceIdpRrn": null,
                "sourceIdpService": null,
                "sourceIdpUsername": null,
                "sourcePublic": false,
                "sourceResourceId": "arn:aws:trail:us-west-1:888888888888:trail/control",
                "sourceResourceName": "i-33333333333333333",
                "sourceResourceType": "instance"
            },
            {
                "accessedResourcesCount": null,
                "destCloudAccount": "AWS-JLo",
                "destCloudRegion": "*",
                "destCloudResourceRrn": null,
                "destCloudServiceName": "ssm",
                "destCloudType": "AWS",
                "destResourceId": "*",
                "destResourceName": "*",
                "destResourceType": "managed-instance",
                "effectiveActionName": "ssm:UpdateInstanceInformation",
                "exceptions": [
                    {
                        "messageCode": "CLOUD_EVENT_NOT_SUPPORTED"
                    },
                    {
                        "messageCode": "AWS_ROOT_ACCOUNT_IS_NOT_ONBOARDED"
                    }
                ],
                "grantedByCloudEntityId": "arn:aws:arn:aws:trail:us-west-1:888888888888:trail/control",
                "grantedByCloudEntityName": "service-role/AWSCloud9SSMAccessRole",
                "grantedByCloudEntityRrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
                "grantedByCloudEntityType": "role",
                "grantedByCloudPolicyId": "arn:aws:trail:us-west-1:888888888888:trail/control",
                "grantedByCloudPolicyName": "AWSCloud9SSMInstanceProfile",
                "grantedByCloudPolicyRrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
                "grantedByCloudPolicyType": "AWS Managed Policy",
                "grantedByCloudType": "AWS",
                "grantedByLevelId": null,
                "grantedByLevelName": null,
                "grantedByLevelRrn": null,
                "grantedByLevelType": "",
                "id": "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",
                "isWildCardDestCloudResourceName": true,
                "lastAccessDate": null,
                "lastAccessStatus": "NOT_AVAILABLE",
                "sourceCloudAccount": "AWS-JLo",
                "sourceCloudRegion": "AWS Oregon",
                "sourceCloudResourceRrn": "rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25",
                "sourceCloudServiceName": "ec2",
                "sourceCloudType": "AWS",
                "sourceIdpDomain": null,
                "sourceIdpEmail": null,
                "sourceIdpGroup": null,
                "sourceIdpRrn": null,
                "sourceIdpService": null,
                "sourceIdpUsername": null,
                "sourcePublic": false,
                "sourceResourceId": "arn:aws:trail:us-west-1:888888888888:trail/control",
                "sourceResourceName": "i-33333333333333333",
                "sourceResourceType": "instance"
            }
        ],
        "PermissionPageToken": {
            "nextPageToken": "token2"
        }
    }
}
```

#### Human Readable Output

>Showing 2 of 20261 results:
>### Permissions Details:
>|Id|Source Cloud Type|Source Cloud Account|Source Resource Id|Destination Cloud Type|Destination Cloud Service Name|Destination Resource Type|Effective Action Name|Granted By Cloud Type|Granted By Cloud Policy Id|Granted By Cloud Policy Name|Granted By Cloud Policy Type|Granted By Cloud Policy Rrn|Granted By Cloud Entity Id|Granted By Cloud Entity Name|Granted By Cloud Entity Rrn|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj | AWS | AWS-JLo | arn:aws:trail:us-west-1:888888888888:trail/control | AWS | ec2 | instance | ssm:UpdateInstanceInformation | AWS | arn:aws:trail:us-west-1:888888888888:trail/control | AWSCloud9SSMInstanceProfile | AWS Managed Policy | rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25 | arn:aws:iam::555555555555:role/service-role/AWSCloud9SSMAccessRole | service-role/AWSCloud9SSMAccessRole | rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25 |
>| kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk | AWS | AWS-JLo | arn:aws:trail:us-west-1:888888888888:trail/control | AWS | ssm | managed-instance | ssm:UpdateInstanceInformation | AWS | arn:aws:trail:us-west-1:888888888888:trail/control | AWSCloud9SSMInstanceProfile | AWS Managed Policy | rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25 | arn:aws:iam::555555555555:role/service-role/AWSCloud9SSMAccessRole | service-role/AWSCloud9SSMAccessRole | rrn::name:place:111:a1b2:a%3Ajj55-2023-01-29-09-25 |
>### Next Page Token:
>token2

### Access Keys

***
Access keys are a secure way to enable programmatic access to the Prisma Cloud API. By default, only the System Admin has API access and can enable API access for other administrators. If you have API access, you can create up to two access keys.

A service account is a special Prisma Cloud identity used to access Prisma Cloud programmatically via API.

To create a service account, see [Add Service Accounts On Prisma Cloud
](https://docs.prismacloud.io/en/enterprise-edition/content-collections/administration/add-service-account-prisma-cloud)
#### Base Command

`prisma-cloud-access-key-create`


#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------| --- | --- |
| name              | Access key name. | Required | 
| expires-on             | Timestamp in milliseconds when access key expires. Default:0. | Optional | 

#### Context Output

| **Path**                  | **Type** | **Description**       |
|---------------------------| --- |-----------------------|
| PrismaCloud.AccessKeys.id  | String | Access key ID.        | 
| PrismaCloud.AccessKeys.secretKey | String | Access key secret. |

#### Command example
```!prisma-cloud-access-key-create name=MyNewKey```
#### Context Example
```json
{
    "PrismaCloud": {
        "AccessKeys": [
            {
                "Id": "Id",
                "Secret Key": "Secret Key"
            }
        ]
    }
}
```

`prisma-cloud-access-keys-list`

#### Input

| **Argument Name** | **Description** | **Required** |
|-------------------| --- | --- |
| access-key             | Returns the metadata of the access key that has the specified ID. | Optional | 
| limit           | Maximum number of entries to return. | Optional | 

#### Context Output

| **Path**                           | **Type** | **Description**             |
|------------------------------------|----------|-----------------------------|
| PrismaCloud.AccessKeys.id          | String   | Access key ID.               | 
| PrismaCloud.AccessKeys.name        | String   | The name of the access key.                        |
| PrismaCloud.AccessKeys.createdBy   | String   | The user who created the access key.                  | 
| PrismaCloud.AccessKeys.createdTs   | String   | Time access key was created. |
| PrismaCloud.AccessKeys.expiresOn   | String   | The time the access key expires.       |
| PrismaCloud.AccessKeys.lastUsedTime | String   | The last time the access key was used.        | 
| PrismaCloud.AccessKeys.status      | String   | Access key status.           |
| PrismaCloud.AccessKeys.role.id     | String   | User role ID.       | 
| PrismaCloud.AccessKeys.role.name   | String   | User role name.              |
| PrismaCloud.AccessKeys.roleType    | String   | User role permission type.   | 
| PrismaCloud.AccessKeys.username    | String   | Access key user name.        |

#### Command example
```!prisma-cloud-access-keys-list limit=2```
#### Context Example
```json
{
    "PrismaCloud": {
        "AccessKeys": [
            {
                "id": "string",
                "name": "string",
                "createdBy": "string",
                "createdTs": "number",
                "lastUsedTime": "number",
                "status": "string",
                "expiresOn": "number",
                "role": {
                    "id": "string",
                    "name": "string"
                },
                "roleType": "string",
                "username": "string"
            },
            {
                "id": "string",
                "name": "string",
                "createdBy": "string",
                "createdTs": "number",
                "lastUsedTime": "number",
                "status": "string",
                "expiresOn": "number",
                "role": {
                    "id": "string",
                    "name": "string"
                },
                "roleType": "string",
                "username": "string"
            }
        ]
    }
}
```

`prisma-cloud-access-key-disable`

#### Input

| **Argument Name** | **Description**                                              | **Required** |
|-------------------|--------------------------------------------------------------| --- |
| access-key              | Access key ID.                                                | Required | 

#### Command example
```!prisma-cloud-access-key-disable access-key=id```

#### Human Readable Output

> Access key mockmock-mock-mock-mock-mockmockmock was disabled successfully

`prisma-cloud-access-key-enable`

#### Input

| **Argument Name** | **Description**                                              | **Required** |
|-------------------|--------------------------------------------------------------| --- |
| access-key              | Access key ID.                                                | Required |

#### Command example
```!prisma-cloud-access-key-enable access-key=id```

#### Human Readable Output

> Access key mockmock-mock-mock-mock-mockmockmock was enabled successfully

`prisma-cloud-access-key-delete`

#### Input

| **Argument Name** | **Description**                                              | **Required** |
|-------------------|--------------------------------------------------------------| --- |
| access-key              | Access key ID.                                                | Required | 

#### Command example
```!prisma-cloud-access-key-delete access-key=id```

#### Human Readable Output

> Access key mockmock-mock-mock-mock-mockmockmock was successfully deleted successfully

## Breaking changes from the previous version of this integration - Prisma Cloud v2
The following sections list the changes in this version.

### Commands
#### The following commands were deprecated in this version because they are not supported by the API anymore:
* ***redlock-list-scans***
* *redlock-get-scan-status***
* ***redlock-get-scan-results***

#### The following commands were replaced in this version:
* ***redlock-dismiss-alerts*** - this command is replaced by ***prisma-cloud-alert-dismiss***.
* ***redlock-get-alert-details*** - this command is replaced by ***prisma-cloud-alert-get-details***.
* ***redlock-get-remediation-details*** - this command is replaced by ***prisma-cloud-remediation-command-list***.
* ***redlock-get-rql-response*** - this command is replaced by ***prisma-cloud-config-search***.
* *redlock-list-alert-filters* - this command is replaced by *prisma-cloud-alert-filter-list*.
* *redlock-reopen-alerts* - this command is replaced by *prisma-cloud-alert-reopen*.
* *redlock-search-alerts* - this command is replaced by *prisma-cloud-alert-search*.
* *redlock-search-config* - this command is replaced by *prisma-cloud-config-search*.
* *redlock-search-event* - this command is replaced by *prisma-cloud-event-search*.
* *redlock-search-network* - this command is replaced by *prisma-cloud-network-search*.


## Additional Considerations for this version
* "Risk detail" was removed from all commands because it is not supported by the API anymore.
* Commands from the previous version were kept in order to make to transition from v1 to v2 easy for existing playbooks. We encourage to use the new version of each command.

### prisma-cloud-code-issues-list

***
Retrieves the code errors detected by Application Security during periodic scans.

#### Base Command

`prisma-cloud-code-issues-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| git_users | Comma-separated list of names of Git users. | Optional | 
| branch | A branch name. | Optional | 
| code_categories | Comma-separated list of code issue categories. Is also available as a search criteria (search_scopes). Possible values are: IacMisconfiguration, IacExternalModule, ImageReferencerVul, ImageReferencerLicenses, Vulnerabilities, Licenses, Secrets. | Optional | 
| iac_categories | Comma-separated list of categories related to Infrastructure-as-Code (IaC) issues. Possible values are: IAM, Monitoring, Networking, Kubernetes, General, Storage, Public, Drift, Compute. | Optional | 
| iac_labels | Comma-separated list of labels associated with Infrastructure-as-Code (IaC). Possible values are: CustomPolicy, HasFix. | Optional | 
| file_types | Comma-separated list of file types. Possible values are: yml, yaml, json, template, py, js, properties, pem, php, xml, ts, env, Dockerfile, java, rb, sum, mod, cs, txt, bicep, hcl, gradle, kts, lock, config, csproj, dependencies. | Optional | 
| fixable_only | Whether to retrieve only fixable issues. Recommended to use this argument with another argument code_categories ,for example. Possible values are: true, false. | Optional | 
| repositories | Comma-separated list of repository names. | Optional | 
| secrets_risk_factors | Comma-separated list of risk factors related to secrets. Possible values are: PublicRepository, PrivateRepository, User, Privileged, Valid, Invalid, Unknown, FoundInHistory. | Optional | 
| search_scopes | Comma-separated list of specific areas or categories within which to search. When specifying `search_scopes`, `search_term` argument is required. Possible values are: IacMisconfiguration, IacExternalModule, ImageReferencerVul, ImageReferencerLicenses, Vulnerabilities, Licenses, Secrets. | Optional | 
| severities | Comma-separated list of the criticality of issues. Possible values are: INFO, LOW, MEDIUM, HIGH, CRITICAL. | Optional | 
| vulnerability_risk_factors | Comma-separated list of risk factors for vulnerabilities. Possible values are: AttackComplexity, AttackVector, DoS, HasFix, RemoteExecution, ExploitInTheWild, ExploitPOC, IsUsed. | Optional | 
| search_term | A keyword or phrase used to narrow down results within specific scopes (like a particular vulnerability). It's needed if you are filtering results by search_scopes. | Optional | 
| iac_tags | An infrastructure-as-code (IaC) resource. Relevant only to- IacMisconfiguration,Vulnerabilities. | Optional | 
| license_type | Comma-separated list of license types. | Optional | 
| check_status | Status of checks. Possible values are: Error, Passed, Suppressed, FixPendin. | Optional | 
| limit | The limit of issues to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.CodeIssue.modifiedOn | String | The date and time when the code issue was last modified. | 
| PrismaCloud.CodeIssue.isPublic | String | Indicates whether the repository or resource is publicly accessible \(true/false\). | 
| PrismaCloud.CodeIssue.fileType | String | The type of file where the issue was detected \(e.g., \`.js\`, \`.py\`\). | 
| PrismaCloud.CodeIssue.secretCommitRemove | String | The commit identifier where a secret was removed. | 
| PrismaCloud.CodeIssue.secretCommitAdd | String | The commit identifier where a secret was added. | 
| PrismaCloud.CodeIssue.gitUser | String | The username of the person who made the commit associated with the code issue. | 
| PrismaCloud.CodeIssue.codePath | String | The path to the code file where the issue was detected. | 
| PrismaCloud.CodeIssue.codeCategory | String | The category or classification of the detected issue \(e.g., security, compliance\). | 
| PrismaCloud.CodeIssue.author | String | The original author of the code where the issue was detected. | 
| PrismaCloud.CodeIssue.repositoryUuid | String | The unique identifier of the repository where the issue was found. | 
| PrismaCloud.CodeIssue.path | String | The path in the repository where the issue was detected. | 
| PrismaCloud.CodeIssue.repositorySource | String | The source of the repository \(e.g., GitHub, Bitbucket\). | 
| PrismaCloud.CodeIssue.firstDetected | String | The date and time when the code issue was first detected. | 
| PrismaCloud.CodeIssue.codeIssueLine | String | The line number in the code where the issue was detected. | 
| PrismaCloud.CodeIssue.labels | String | Labels associated with the code issue for classification or categorization. | 
| PrismaCloud.CodeIssue.labels.label | String | A specific label related to the code issue. | 
| PrismaCloud.CodeIssue.labels.metadata.imageName | String | The name of the image associated with the label metadata. | 
| PrismaCloud.CodeIssue.policy | String | The policy that was violated by the detected issue. | 
| PrismaCloud.CodeIssue.repository | String | The name of the repository where the issue was found. | 
| PrismaCloud.CodeIssue.resourceName | String | The name of the resource associated with the code issue. | 
| PrismaCloud.CodeIssue.resourceScanType | String | The type of scan that detected the issue \(e.g., static analysis, secret detection\). | 
| PrismaCloud.CodeIssue.resourceUuid | String | The unique identifier of the resource associated with the code issue. | 
| PrismaCloud.CodeIssue.severity | String | The severity level of the detected issue \(e.g., High, Medium, Low\). | 
| PrismaCloud.CodeIssue.violationId | String | The unique identifier for the policy violation related to the code issue. | 
| PrismaCloud.CodeIssue.causePackageId | String | The ID of the package that caused the issue. | 
| PrismaCloud.CodeIssue.causePackageName | String | The name of the package that caused the issue. | 
| PrismaCloud.CodeIssue.cveUuid | String | The unique identifier of the Common Vulnerabilities and Exposures \(CVE\) related to the issue. | 
| PrismaCloud.CodeIssue.cvss | String | The Common Vulnerability Scoring System \(CVSS\) score for the detected issue. | 
| PrismaCloud.CodeIssue.fixVersion | String | The version of the code or package that contains the fix for the issue. | 
| PrismaCloud.CodeIssue.pr | String | The pull request \(PR\) associated with resolving the code issue. | 
| PrismaCloud.CodeIssue.resourceId | String | The identifier of the resource related to the code issue. | 
| PrismaCloud.CodeIssue.riskFactors | String | Risk factors associated with the code issue, such as high-impact areas or sensitive data. | 
| PrismaCloud.CodeIssue.isIndirectPackage | String | Indicates whether the issue is from an indirect package \(true/false\). | 

### prisma-cloud-asset-alerts-get

***
Returns detailed information for the asset alerts with the given ID.

#### Base Command

`prisma-cloud-asset-alerts-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Unified asset ID or RRN (Restricted Resource Name). | Required | 
| finding_type | External finding types. Possible values are: COMPLIANCE_CIS, GUARD_DUTY_HOST, GUARD_DUTY_IAM, INSPECTOR_RBA, INSPECTOR_SBP, NETWORK_REACHABILITY, AZURE_SECURITY_CENTER_ALERTS, UNCLASSIFIED, COMMAND_AND_CONTROL, CREDENTIAL_ACCESS, CROSS_ACCOUNT_TRUST, DATA_EXFILTRATION, DEFENSE_EVASION, DISCOVERY, HIGH_PRIVILEGED_ROLE, INITIAL_ACCESS, INTERNET_EXPOSURE, KEYS_AND_SECRETS, LATERAL_MOVEMENT, MALWARE, MFA, MISCONFIGURATION, NETWORK_ANOMALY, PRIVILEGE_ESCALATION, RECONNAISSANCE, RESOURCE_HIJACKING, SSH_BRUTE_FORCE, UNAUTHORIZED_ACCESS, UNENCRYPTED_DATA, UNUSED_PRIVILEGES, USER_ANOMALY, WEAK_PASSWORD, SENSITIVE_DATA_EXPOSURE, INJECTIONS, VULNERABILITY_SCANNING, SHELLSHOCK, KNOWN_BOTS, UNKNOWN_BOTS, VIRTUAL_PATCHES, WEB_ATTACK, BOT_ACTIVITY, WEB_SCRAPING, CUSTOM, VULNERABILITY, HOST_VULNERABILITY_CVE, CONTAINER_IMAGE_VULNERABILITY_CVE, VIRTUAL_IMAGE_VULNERABILITY_CVE, SERVERLESS_VULNERABILITY, PACKAGE_VULNERABILITY. | Optional | 
| risk_factors | Comma-separated list of external finding risk factors. Possible values are: CRITICAL_SEVERITY, HIGH_SEVERITY, MEDIUM_SEVERITY, HAS_FIX, REMOTE_EXECUTION, DOS, RECENT_VULNERABILITY, EXPLOIT_EXISTS, ATTACK_COMPLEXITY_LOW, ATTACK_VECTOR_NETWORK, REACHABLE_FROM_THE_INTERNET, LISTENING_PORTS, CONTAINER_IS_RUNNING_AS_ROOT, NO_MANDATORY_SECURITY_PROFILE_APPLIED, RUNNING_AS_PRIVILEGED_CONTAINER, PACKAGE_IN_USE, DOS_LOW, DOS_HIGH, EXPLOIT_EXISTS_IN_THE_WILD, EXPLOIT_EXISTS_POC, SENSITIVE_INFORMATION, ROOT_MOUNT, RUNTIME_SOCKET, HOST_ACCESS. | Optional | 
| timeline_item_id | Timeline item ID. | Optional | 
| alert_ids | Comma-separated list of alert IDs. | Optional | 
| limit | Limit number of records. | Optional | 
| permission_type | Permissions type. | Optional | 
| page_token | Next page token. | Optional | 
| prisma_cloud_findings_only | Filter Hyperion findings. Possible values are: true, false. | Optional | 
| vulnerability_info_type_id | CVE ID, package ID, or layer ID. The value needs to be fetched from one of the group by API calls. | Optional | 
| vulnerability_info_type | Supported vulnerability types. Possible values are: CVE, PACKAGE, LAYER. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.AssetAlerts.problem.title | String | The title of the problem. | 
| PrismaCloud.AssetAlerts.problem.status.statusCode | Number | The status code of the problem. | 
| PrismaCloud.AssetAlerts.problem.status.reasonPhrase | String | The reason for the problem. | 
| PrismaCloud.AssetAlerts.problem.detail | String | The details of the problem. | 
| PrismaCloud.AssetAlerts.problem.instance | String | The instance of the problem. | 
| PrismaCloud.AssetAlerts.problem.type | String | The type of the problem. | 
| PrismaCloud.AssetAlerts.problem.parameters | Unknown | The parameters of the problem. | 
| PrismaCloud.AssetAlerts.id | String | The ID of the asset alert. | 
| PrismaCloud.AssetAlerts.severity | String | The severity of the asset alert. | 
| PrismaCloud.AssetAlerts.policyId | String | The policy ID of the asset alert. | 
| PrismaCloud.AssetAlerts.isHyperionPolicy | Boolean | The hyperion policy of the asset alert. | 
| PrismaCloud.AssetAlerts.policyType | String | The policy type of the asset alert. | 
| PrismaCloud.AssetAlerts.policyName | String | The policy name of the asset alert. | 
| PrismaCloud.AssetAlerts.policyDescription | String | The policy description of the asset alert. | 
| PrismaCloud.AssetAlerts.alertTime | Number | The alert time of the asset alert. | 

### prisma-cloud-asset-network-get

***
Returns detailed information for the asset network with the given ID.

#### Base Command

`prisma-cloud-asset-network-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Unified asset ID or RRN (Restricted Resource Name). | Required | 
| finding_type | External finding types. Possible values are: COMPLIANCE_CIS, GUARD_DUTY_HOST, GUARD_DUTY_IAM, INSPECTOR_RBA, INSPECTOR_SBP, NETWORK_REACHABILITY, AZURE_SECURITY_CENTER_ALERTS, UNCLASSIFIED, COMMAND_AND_CONTROL, CREDENTIAL_ACCESS, CROSS_ACCOUNT_TRUST, DATA_EXFILTRATION, DEFENSE_EVASION, DISCOVERY, HIGH_PRIVILEGED_ROLE, INITIAL_ACCESS, INTERNET_EXPOSURE, KEYS_AND_SECRETS, LATERAL_MOVEMENT, MALWARE, MFA, MISCONFIGURATION, NETWORK_ANOMALY, PRIVILEGE_ESCALATION, RECONNAISSANCE, RESOURCE_HIJACKING, SSH_BRUTE_FORCE, UNAUTHORIZED_ACCESS, UNENCRYPTED_DATA, UNUSED_PRIVILEGES, USER_ANOMALY, WEAK_PASSWORD, SENSITIVE_DATA_EXPOSURE, INJECTIONS, VULNERABILITY_SCANNING, SHELLSHOCK, KNOWN_BOTS, UNKNOWN_BOTS, VIRTUAL_PATCHES, WEB_ATTACK, BOT_ACTIVITY, WEB_SCRAPING, CUSTOM, VULNERABILITY, HOST_VULNERABILITY_CVE, CONTAINER_IMAGE_VULNERABILITY_CVE, VIRTUAL_IMAGE_VULNERABILITY_CVE, SERVERLESS_VULNERABILITY, PACKAGE_VULNERABILITY. | Optional | 
| risk_factors | Comma-separated list of external finding risk factors. Possible values are: CRITICAL_SEVERITY, HIGH_SEVERITY, MEDIUM_SEVERITY, HAS_FIX, REMOTE_EXECUTION, DOS, RECENT_VULNERABILITY, EXPLOIT_EXISTS, ATTACK_COMPLEXITY_LOW, ATTACK_VECTOR_NETWORK, REACHABLE_FROM_THE_INTERNET, LISTENING_PORTS, CONTAINER_IS_RUNNING_AS_ROOT, NO_MANDATORY_SECURITY_PROFILE_APPLIED, RUNNING_AS_PRIVILEGED_CONTAINER, PACKAGE_IN_USE, DOS_LOW, DOS_HIGH, EXPLOIT_EXISTS_IN_THE_WILD, EXPLOIT_EXISTS_POC, SENSITIVE_INFORMATION, ROOT_MOUNT, RUNTIME_SOCKET, HOST_ACCESS. | Optional | 
| timeline_item_id | Timeline item ID. | Optional | 
| alert_ids | Comma-separated list of alert IDs. | Optional | 
| limit | Limit number of records. | Optional | 
| permission_type | Permissions type. | Optional | 
| page_token | Next page token. | Optional | 
| prisma_cloud_findings_only | Filter Hyperion findings. Possible values are: true, false. | Optional | 
| vulnerability_info_type_id | CVE ID, package ID, or layer ID. The value needs to be fetched from one of the group by API calls. | Optional | 
| vulnerability_info_type | Supported vulnerability types. Possible values are: CVE, PACKAGE, LAYER. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.AssetNetwork.problem.title | String | The title of the problem. | 
| PrismaCloud.AssetNetwork.problem.status.statusCode | Number | The status code of the problem. | 
| PrismaCloud.AssetNetwork.problem.status.reasonPhrase | String | The reason for the problem. | 
| PrismaCloud.AssetNetwork.problem.detail | String | The details of the problem. | 
| PrismaCloud.AssetNetwork.problem.instance | String | The instance of the problem. | 
| PrismaCloud.AssetNetwork.problem.type | String | The type of the problem. | 
| PrismaCloud.AssetNetwork.problem.parameters | Unknown | The parameters of the problem. | 
| PrismaCloud.AssetNetwork.id | Number | The ID of the asset network. | 
| PrismaCloud.AssetNetwork.access | String | The access of the asset network. | 
| PrismaCloud.AssetNetwork.direction | String | The direction of the asset network. | 
| PrismaCloud.AssetNetwork.ips | String | The IPS of the asset network. | 
| PrismaCloud.AssetNetwork.ports | String | The ports of the asset network. | 
| PrismaCloud.AssetNetwork.protocol | String | The protocol of the asset network. | 
| PrismaCloud.AssetNetwork.priority | Number | The priority of the asset network. | 

### prisma-cloud-asset-vulnerabilities-get

***
Returns detailed information for the asset vulnerabilities with the given ID.

#### Base Command

`prisma-cloud-asset-vulnerabilities-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Unified asset ID or RRN (Restricted Resource Name). | Required | 
| finding_type | External finding types. Possible values are: COMPLIANCE_CIS, GUARD_DUTY_HOST, GUARD_DUTY_IAM, INSPECTOR_RBA, INSPECTOR_SBP, NETWORK_REACHABILITY, AZURE_SECURITY_CENTER_ALERTS, UNCLASSIFIED, COMMAND_AND_CONTROL, CREDENTIAL_ACCESS, CROSS_ACCOUNT_TRUST, DATA_EXFILTRATION, DEFENSE_EVASION, DISCOVERY, HIGH_PRIVILEGED_ROLE, INITIAL_ACCESS, INTERNET_EXPOSURE, KEYS_AND_SECRETS, LATERAL_MOVEMENT, MALWARE, MFA, MISCONFIGURATION, NETWORK_ANOMALY, PRIVILEGE_ESCALATION, RECONNAISSANCE, RESOURCE_HIJACKING, SSH_BRUTE_FORCE, UNAUTHORIZED_ACCESS, UNENCRYPTED_DATA, UNUSED_PRIVILEGES, USER_ANOMALY, WEAK_PASSWORD, SENSITIVE_DATA_EXPOSURE, INJECTIONS, VULNERABILITY_SCANNING, SHELLSHOCK, KNOWN_BOTS, UNKNOWN_BOTS, VIRTUAL_PATCHES, WEB_ATTACK, BOT_ACTIVITY, WEB_SCRAPING, CUSTOM, VULNERABILITY, HOST_VULNERABILITY_CVE, CONTAINER_IMAGE_VULNERABILITY_CVE, VIRTUAL_IMAGE_VULNERABILITY_CVE, SERVERLESS_VULNERABILITY, PACKAGE_VULNERABILITY. | Optional | 
| risk_factors | Comma-separated list of external finding risk factors. Possible values are: CRITICAL_SEVERITY, HIGH_SEVERITY, MEDIUM_SEVERITY, HAS_FIX, REMOTE_EXECUTION, DOS, RECENT_VULNERABILITY, EXPLOIT_EXISTS, ATTACK_COMPLEXITY_LOW, ATTACK_VECTOR_NETWORK, REACHABLE_FROM_THE_INTERNET, LISTENING_PORTS, CONTAINER_IS_RUNNING_AS_ROOT, NO_MANDATORY_SECURITY_PROFILE_APPLIED, RUNNING_AS_PRIVILEGED_CONTAINER, PACKAGE_IN_USE, DOS_LOW, DOS_HIGH, EXPLOIT_EXISTS_IN_THE_WILD, EXPLOIT_EXISTS_POC, SENSITIVE_INFORMATION, ROOT_MOUNT, RUNTIME_SOCKET, HOST_ACCESS. | Optional | 
| timeline_item_id | Timeline item ID. | Optional | 
| alert_ids | Comma-separated list of alert IDs. | Optional | 
| limit | Limit number of records. | Optional | 
| permission_type | Permissions type. | Optional | 
| page_token | Next page token. | Optional | 
| prisma_cloud_findings_only | Filter Hyperion findings. Possible values are: true, false. | Optional | 
| vulnerability_info_type_id | CVE ID, package ID, or layer ID. The value needs to be fetched from one of the group by API calls. | Optional | 
| vulnerability_info_type | Supported vulnerability types. Possible values are: CVE, PACKAGE, LAYER. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.AssetVulnerabilities.problem.title | String | The title of the problem. | 
| PrismaCloud.AssetVulnerabilities.problem.status.statusCode | Number | The status code of the problem. | 
| PrismaCloud.AssetVulnerabilities.problem.status.reasonPhrase | String | The reason for the problem. | 
| PrismaCloud.AssetVulnerabilities.problem.detail | String | The details of the problem. | 
| PrismaCloud.AssetVulnerabilities.problem.instance | String | The instance of the problem. | 
| PrismaCloud.AssetVulnerabilities.problem.type | String | The type of the problem. | 
| PrismaCloud.AssetVulnerabilities.problem.parameters | Unknown | The parameters of the problem. | 
| PrismaCloud.AssetVulnerabilities.accountId | String | The account ID of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.count | String | The count of asset vulnerabilities. | 
| PrismaCloud.AssetVulnerabilities.createdOn | Number | The created on of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.customerId | Number | The customer ID of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.cveId | String | The CVE ID of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.description | String | The description of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.externalId | Number | The external ID of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.id | String | The ID of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.normalizedName | String | The normalized name of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.normalizedNames | String | The normalized names of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.nvdUrl | String | The nvd URL of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.link | String | The link of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.rawData | String | The raw data of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.regionId | String | The region ID of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.resourceCloudId | String | The resource cloud ID of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.resourceId | Number | The resource ID of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.resourceUrl | String | The resource URL of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.riskFactors | String | The risk factors of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.rlUpdatedOn | Number | The rl updated on of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.scanId | String | The scan ID of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.score | String | The score of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.severity | String | The severity of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.source | String | The source of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.sourceData | Unknown | The source data of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.status | String | The status of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.title | String | The title of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.type | String | The type of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.packageName | String | The package name of the asset vulnerability. | 
| PrismaCloud.AssetVulnerabilities.updatedOn | Number | The updated on of the asset vulnerability. | 

### prisma-cloud-asset-get

***
Returns detailed information for the asset with the given ID.

#### Base Command

`prisma-cloud-asset-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Unified Asset ID or RRN (Restricted Resource Name). | Required | 
| finding_type | External finding types. Possible values are: COMPLIANCE_CIS, GUARD_DUTY_HOST, GUARD_DUTY_IAM, INSPECTOR_RBA, INSPECTOR_SBP, NETWORK_REACHABILITY, AZURE_SECURITY_CENTER_ALERTS, UNCLASSIFIED, COMMAND_AND_CONTROL, CREDENTIAL_ACCESS, CROSS_ACCOUNT_TRUST, DATA_EXFILTRATION, DEFENSE_EVASION, DISCOVERY, HIGH_PRIVILEGED_ROLE, INITIAL_ACCESS, INTERNET_EXPOSURE, KEYS_AND_SECRETS, LATERAL_MOVEMENT, MALWARE, MFA, MISCONFIGURATION, NETWORK_ANOMALY, PRIVILEGE_ESCALATION, RECONNAISSANCE, RESOURCE_HIJACKING, SSH_BRUTE_FORCE, UNAUTHORIZED_ACCESS, UNENCRYPTED_DATA, UNUSED_PRIVILEGES, USER_ANOMALY, WEAK_PASSWORD, SENSITIVE_DATA_EXPOSURE, INJECTIONS, VULNERABILITY_SCANNING, SHELLSHOCK, KNOWN_BOTS, UNKNOWN_BOTS, VIRTUAL_PATCHES, WEB_ATTACK, BOT_ACTIVITY, WEB_SCRAPING, CUSTOM, VULNERABILITY, HOST_VULNERABILITY_CVE, CONTAINER_IMAGE_VULNERABILITY_CVE, VIRTUAL_IMAGE_VULNERABILITY_CVE, SERVERLESS_VULNERABILITY, PACKAGE_VULNERABILITY. | Optional | 
| risk_factors | Comma-separated list of external finding risk factors. Possible values are: CRITICAL_SEVERITY, HIGH_SEVERITY, MEDIUM_SEVERITY, HAS_FIX, REMOTE_EXECUTION, DOS, RECENT_VULNERABILITY, EXPLOIT_EXISTS, ATTACK_COMPLEXITY_LOW, ATTACK_VECTOR_NETWORK, REACHABLE_FROM_THE_INTERNET, LISTENING_PORTS, CONTAINER_IS_RUNNING_AS_ROOT, NO_MANDATORY_SECURITY_PROFILE_APPLIED, RUNNING_AS_PRIVILEGED_CONTAINER, PACKAGE_IN_USE, DOS_LOW, DOS_HIGH, EXPLOIT_EXISTS_IN_THE_WILD, EXPLOIT_EXISTS_POC, SENSITIVE_INFORMATION, ROOT_MOUNT, RUNTIME_SOCKET, HOST_ACCESS. | Optional | 
| timeline_item_id | Timeline item ID. | Optional | 
| alert_ids | Comma-separated list of alert IDs. | Optional | 
| limit | Limit number of records. | Optional | 
| permission_type | Permissions type. | Optional | 
| page_token | Next page token. | Optional | 
| prisma_cloud_findings_only | Filter Hyperion findings. Possible values are: true, false. | Optional | 
| vulnerability_info_type_id | CVE ID, Package ID, or Layer ID. The value needs to be fetched from one of the groups by API calls. | Optional | 
| vulnerability_info_type | Supported vulnerability types. Possible values are: CVE, PACKAGE, LAYER. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.Asset.problem.title | String | The title of the problem. | 
| PrismaCloud.Asset.problem.status.statusCode | Number | The status code of the problem. | 
| PrismaCloud.Asset.problem.status.reasonPhrase | String | The reason for the problem. | 
| PrismaCloud.Asset.problem.detail | String | The details of the problem. | 
| PrismaCloud.Asset.problem.instance | String | The instance of the problem. | 
| PrismaCloud.Asset.problem.type | String | The type of the problem. | 
| PrismaCloud.Asset.problem.parameters | Unknown | The parameters of the problem. | 
| PrismaCloud.Asset.id | String | The ID of the asset. | 
| PrismaCloud.Asset.prismaId | String | The Prisma ID of the asset. | 
| PrismaCloud.Asset.appName | String | The app name of the asset. | 
| PrismaCloud.Asset.externalAssetId | String | The external asset ID of the asset. | 
| PrismaCloud.Asset.assetTypeId | Number | The asset type ID of the asset. | 
| PrismaCloud.Asset.cloudType | String | The cloud type of the asset. | 
| PrismaCloud.Asset.createdTs | Number | The creation timestamp of the asset. | 
| PrismaCloud.Asset.insertTs | Number | The insertion timestamp of the asset. | 
| PrismaCloud.Asset.data | Unknown | The data of the asset. | 
| PrismaCloud.Asset.dynamicData | Unknown | The dynamic data of the asset. | 
| PrismaCloud.Asset.riskGrade | String | The risk grade of the asset. | 
| PrismaCloud.Asset.stateId | String | The state ID of the asset. | 
| PrismaCloud.Asset.name | String | The name of the asset. | 
| PrismaCloud.Asset.regionId | String | The region ID of the asset. | 
| PrismaCloud.Asset.regionName | String | The region name of the asset. | 
| PrismaCloud.Asset.altAssetId | String | The alternative asset ID of the asset. | 
| PrismaCloud.Asset.url | String | The URL of the asset. | 
| PrismaCloud.Asset.vpcId | String | The VPC ID of the asset. | 
| PrismaCloud.Asset.vpcExternalAssetId | String | The VPC external asset ID of the asset. | 
| PrismaCloud.Asset.vpcName | String | The VPC name of the asset. | 
| PrismaCloud.Asset.tags | Unknown | The tags of the asset. | 
| PrismaCloud.Asset.relationshipCounts | Number | The relationship counts of the asset. | 
| PrismaCloud.Asset.vulnerabilityCounts | Unknown | The vulnerability counts of the asset. | 
| PrismaCloud.Asset.accountName | String | The account name of the asset. | 
| PrismaCloud.Asset.assetType | String | The account type of the asset. | 
| PrismaCloud.Asset.serviceName | String | The service name of the asset. | 
| PrismaCloud.Asset.resourceType | String | The resource type of the asset. | 
| PrismaCloud.Asset.deleted | Boolean | The deletion state of the asset. | 
| PrismaCloud.Asset.assetClassId | String | The asset class ID of the asset. | 
| PrismaCloud.Asset.assetClass | String | The asset class of the asset. | 
| PrismaCloud.Asset.attributes | Unknown | The attributes of the asset. | 
| PrismaCloud.Asset.alertsCount.severity | String | The severity of the alerts of the asset. | 
| PrismaCloud.Asset.alertsCount.count | Number | The alert count of the asset. | 
| PrismaCloud.Asset.ipAddresses | String | The IP addresses of the asset. | 
| PrismaCloud.Asset.trueInternetExposure | String | The internet exposure state of the asset. | 
| PrismaCloud.Asset.dataSecurity | Unknown | The data security of the asset. | 

### prisma-cloud-asset-generic-get

***
Returns detailed information for the asset with the given ID.

#### Base Command

`prisma-cloud-asset-generic-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Unified asset ID or RRN (Restricted Resource Name). | Required | 
| type | Asset domain service query type. Possible values are: external_finding, asset, asset_lite, alerts, alerts_counts, alert_summary, finding_summary, attack_path, attack_path_summary, raw_config, network, timeline, external_integration, asset_data_indicators, relationships, findings, vulnerabilities, permissions, package_info, labels, vulnerability_aggregates, process_info, vulnerabilities_group_by_type, asset_cwp_vulns, app_contexts, attributes, data_security, data_security_summary. Default is asset. | Required | 
| finding_type | External finding types. Possible values are: COMPLIANCE_CIS, GUARD_DUTY_HOST, GUARD_DUTY_IAM, INSPECTOR_RBA, INSPECTOR_SBP, NETWORK_REACHABILITY, AZURE_SECURITY_CENTER_ALERTS, UNCLASSIFIED, COMMAND_AND_CONTROL, CREDENTIAL_ACCESS, CROSS_ACCOUNT_TRUST, DATA_EXFILTRATION, DEFENSE_EVASION, DISCOVERY, HIGH_PRIVILEGED_ROLE, INITIAL_ACCESS, INTERNET_EXPOSURE, KEYS_AND_SECRETS, LATERAL_MOVEMENT, MALWARE, MFA, MISCONFIGURATION, NETWORK_ANOMALY, PRIVILEGE_ESCALATION, RECONNAISSANCE, RESOURCE_HIJACKING, SSH_BRUTE_FORCE, UNAUTHORIZED_ACCESS, UNENCRYPTED_DATA, UNUSED_PRIVILEGES, USER_ANOMALY, WEAK_PASSWORD, SENSITIVE_DATA_EXPOSURE, INJECTIONS, VULNERABILITY_SCANNING, SHELLSHOCK, KNOWN_BOTS, UNKNOWN_BOTS, VIRTUAL_PATCHES, WEB_ATTACK, BOT_ACTIVITY, WEB_SCRAPING, CUSTOM, VULNERABILITY, HOST_VULNERABILITY_CVE, CONTAINER_IMAGE_VULNERABILITY_CVE, VIRTUAL_IMAGE_VULNERABILITY_CVE, SERVERLESS_VULNERABILITY, PACKAGE_VULNERABILITY. | Optional | 
| risk_factors | Comma-separated list of external finding risk factors. Possible values are: CRITICAL_SEVERITY, HIGH_SEVERITY, MEDIUM_SEVERITY, HAS_FIX, REMOTE_EXECUTION, DOS, RECENT_VULNERABILITY, EXPLOIT_EXISTS, ATTACK_COMPLEXITY_LOW, ATTACK_VECTOR_NETWORK, REACHABLE_FROM_THE_INTERNET, LISTENING_PORTS, CONTAINER_IS_RUNNING_AS_ROOT, NO_MANDATORY_SECURITY_PROFILE_APPLIED, RUNNING_AS_PRIVILEGED_CONTAINER, PACKAGE_IN_USE, DOS_LOW, DOS_HIGH, EXPLOIT_EXISTS_IN_THE_WILD, EXPLOIT_EXISTS_POC, SENSITIVE_INFORMATION, ROOT_MOUNT, RUNTIME_SOCKET, HOST_ACCESS. | Optional | 
| timeline_item_id | Timeline item ID. | Optional | 
| alert_ids | Comma-separated list of alert IDs. | Optional | 
| limit | Limit number of records. | Optional | 
| permission_type | Permissions type. | Optional | 
| page_token | Next page token. | Optional | 
| prisma_cloud_findings_only | Filter Hyperion findings. Possible values are: true, false. | Optional | 
| vulnerability_info_type_id | CVE ID, package ID, or layer ID. The value needs to be fetched from one of the group by API calls. | Optional | 
| vulnerability_info_type | Supported vulnerability types. Possible values are: CVE, PACKAGE, LAYER. | Optional | 

#### Context Output

There is no context output for this command.
### prisma-cloud-asset-findings-get

***
Returns detailed information for the asset findings with the given ID.

#### Base Command

`prisma-cloud-asset-findings-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Unified asset ID or RRN (Restricted Resource Name). | Required | 
| finding_type | External finding types. Possible values are: COMPLIANCE_CIS, GUARD_DUTY_HOST, GUARD_DUTY_IAM, INSPECTOR_RBA, INSPECTOR_SBP, NETWORK_REACHABILITY, AZURE_SECURITY_CENTER_ALERTS, UNCLASSIFIED, COMMAND_AND_CONTROL, CREDENTIAL_ACCESS, CROSS_ACCOUNT_TRUST, DATA_EXFILTRATION, DEFENSE_EVASION, DISCOVERY, HIGH_PRIVILEGED_ROLE, INITIAL_ACCESS, INTERNET_EXPOSURE, KEYS_AND_SECRETS, LATERAL_MOVEMENT, MALWARE, MFA, MISCONFIGURATION, NETWORK_ANOMALY, PRIVILEGE_ESCALATION, RECONNAISSANCE, RESOURCE_HIJACKING, SSH_BRUTE_FORCE, UNAUTHORIZED_ACCESS, UNENCRYPTED_DATA, UNUSED_PRIVILEGES, USER_ANOMALY, WEAK_PASSWORD, SENSITIVE_DATA_EXPOSURE, INJECTIONS, VULNERABILITY_SCANNING, SHELLSHOCK, KNOWN_BOTS, UNKNOWN_BOTS, VIRTUAL_PATCHES, WEB_ATTACK, BOT_ACTIVITY, WEB_SCRAPING, CUSTOM, VULNERABILITY, HOST_VULNERABILITY_CVE, CONTAINER_IMAGE_VULNERABILITY_CVE, VIRTUAL_IMAGE_VULNERABILITY_CVE, SERVERLESS_VULNERABILITY, PACKAGE_VULNERABILITY. | Optional | 
| risk_factors | Comma-separated list of external finding risk factors. Possible values are: CRITICAL_SEVERITY, HIGH_SEVERITY, MEDIUM_SEVERITY, HAS_FIX, REMOTE_EXECUTION, DOS, RECENT_VULNERABILITY, EXPLOIT_EXISTS, ATTACK_COMPLEXITY_LOW, ATTACK_VECTOR_NETWORK, REACHABLE_FROM_THE_INTERNET, LISTENING_PORTS, CONTAINER_IS_RUNNING_AS_ROOT, NO_MANDATORY_SECURITY_PROFILE_APPLIED, RUNNING_AS_PRIVILEGED_CONTAINER, PACKAGE_IN_USE, DOS_LOW, DOS_HIGH, EXPLOIT_EXISTS_IN_THE_WILD, EXPLOIT_EXISTS_POC, SENSITIVE_INFORMATION, ROOT_MOUNT, RUNTIME_SOCKET, HOST_ACCESS. | Optional | 
| timeline_item_id | Timeline item ID. | Optional | 
| alert_ids | Comma-separated list of alert IDs. | Optional | 
| limit | Limit number of records. | Optional | 
| permission_type | Permissions type. | Optional | 
| page_token | Next page token. | Optional | 
| prisma_cloud_findings_only | Filter Hyperion findings. Possible values are: true, false. | Optional | 
| vulnerability_info_type_id | CVE ID, package ID, or layer ID. The value needs to be fetched from one of the group by API calls. | Optional | 
| vulnerability_info_type | Supported vulnerability types. Possible values are: CVE, PACKAGE, LAYER. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.AssetFindings.problem.title | String | The title of the problem. | 
| PrismaCloud.AssetFindings.problem.status.statusCode | Number | The status code of the problem. | 
| PrismaCloud.AssetFindings.problem.status.reasonPhrase | String | The reason for the problem. | 
| PrismaCloud.AssetFindings.problem.detail | String | The details of the problem. | 
| PrismaCloud.AssetFindings.problem.instance | String | The instance of the problem. | 
| PrismaCloud.AssetFindings.problem.type | String | The type of the problem. | 
| PrismaCloud.AssetFindings.problem.parameters | Unknown | The parameters of the problem. | 
| PrismaCloud.AssetFindings.accountId | String | The account ID of the asset findings. | 
| PrismaCloud.AssetFindings.count | String | The count of asset findings. | 
| PrismaCloud.AssetFindings.createdOn | Number | The created on of the asset findings. | 
| PrismaCloud.AssetFindings.customerId | Number | The customer ID of the asset findings. | 
| PrismaCloud.AssetFindings.cveId | String | The CVE ID of the asset findings. | 
| PrismaCloud.AssetFindings.description | String | The description of the asset findings. | 
| PrismaCloud.AssetFindings.externalId | Number | The external ID of the asset findings. | 
| PrismaCloud.AssetFindings.id | String | The ID of the asset findings. | 
| PrismaCloud.AssetFindings.normalizedName | String | The normalized name of the asset findings. | 
| PrismaCloud.AssetFindings.normalizedNames | String | The normalized names of the asset findings. | 
| PrismaCloud.AssetFindings.nvdUrl | String | The nvd URL of the asset findings. | 
| PrismaCloud.AssetFindings.link | String | The link of the asset findings. | 
| PrismaCloud.AssetFindings.rawData | String | The raw data of the asset findings. | 
| PrismaCloud.AssetFindings.regionId | String | The region ID of the asset findings. | 
| PrismaCloud.AssetFindings.resourceCloudId | String | The resource cloud ID of the asset findings. | 
| PrismaCloud.AssetFindings.resourceId | Number | The resource ID of the asset findings. | 
| PrismaCloud.AssetFindings.resourceUrl | String | The resource URL of the asset findings. | 
| PrismaCloud.AssetFindings.riskFactors | String | The risk factors of the asset findings. | 
| PrismaCloud.AssetFindings.rlUpdatedOn | Number | The rl updated on of the asset findings. | 
| PrismaCloud.AssetFindings.scanId | String | The scan ID of the asset findings. | 
| PrismaCloud.AssetFindings.score | String | The score of the asset findings. | 
| PrismaCloud.AssetFindings.severity | String | The severity of the asset findings. | 
| PrismaCloud.AssetFindings.source | String | The source of the asset findings. | 
| PrismaCloud.AssetFindings.sourceData | Unknown | The source data of the asset findings. | 
| PrismaCloud.AssetFindings.status | String | The status of the asset findings. | 
| PrismaCloud.AssetFindings.title | String | The title of the asset findings. | 
| PrismaCloud.AssetFindings.type | String | The type of the asset findings. | 
| PrismaCloud.AssetFindings.packageName | String | The package name of the asset findings. | 
| PrismaCloud.AssetFindings.updatedOn | Number | The updated on of the asset findings. | 

### prisma-cloud-asset-relationships-get

***
Returns detailed information for the asset relationships with the given ID.

#### Base Command

`prisma-cloud-asset-relationships-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Unified asset ID or RRN (Restricted Resource Name). | Required | 
| finding_type | External finding types. Possible values are: COMPLIANCE_CIS, GUARD_DUTY_HOST, GUARD_DUTY_IAM, INSPECTOR_RBA, INSPECTOR_SBP, NETWORK_REACHABILITY, AZURE_SECURITY_CENTER_ALERTS, UNCLASSIFIED, COMMAND_AND_CONTROL, CREDENTIAL_ACCESS, CROSS_ACCOUNT_TRUST, DATA_EXFILTRATION, DEFENSE_EVASION, DISCOVERY, HIGH_PRIVILEGED_ROLE, INITIAL_ACCESS, INTERNET_EXPOSURE, KEYS_AND_SECRETS, LATERAL_MOVEMENT, MALWARE, MFA, MISCONFIGURATION, NETWORK_ANOMALY, PRIVILEGE_ESCALATION, RECONNAISSANCE, RESOURCE_HIJACKING, SSH_BRUTE_FORCE, UNAUTHORIZED_ACCESS, UNENCRYPTED_DATA, UNUSED_PRIVILEGES, USER_ANOMALY, WEAK_PASSWORD, SENSITIVE_DATA_EXPOSURE, INJECTIONS, VULNERABILITY_SCANNING, SHELLSHOCK, KNOWN_BOTS, UNKNOWN_BOTS, VIRTUAL_PATCHES, WEB_ATTACK, BOT_ACTIVITY, WEB_SCRAPING, CUSTOM, VULNERABILITY, HOST_VULNERABILITY_CVE, CONTAINER_IMAGE_VULNERABILITY_CVE, VIRTUAL_IMAGE_VULNERABILITY_CVE, SERVERLESS_VULNERABILITY, PACKAGE_VULNERABILITY. | Optional | 
| risk_factors | Comma-separated list of external finding risk factors. Possible values are: CRITICAL_SEVERITY, HIGH_SEVERITY, MEDIUM_SEVERITY, HAS_FIX, REMOTE_EXECUTION, DOS, RECENT_VULNERABILITY, EXPLOIT_EXISTS, ATTACK_COMPLEXITY_LOW, ATTACK_VECTOR_NETWORK, REACHABLE_FROM_THE_INTERNET, LISTENING_PORTS, CONTAINER_IS_RUNNING_AS_ROOT, NO_MANDATORY_SECURITY_PROFILE_APPLIED, RUNNING_AS_PRIVILEGED_CONTAINER, PACKAGE_IN_USE, DOS_LOW, DOS_HIGH, EXPLOIT_EXISTS_IN_THE_WILD, EXPLOIT_EXISTS_POC, SENSITIVE_INFORMATION, ROOT_MOUNT, RUNTIME_SOCKET, HOST_ACCESS. | Optional | 
| timeline_item_id | Timeline item ID. | Optional | 
| alert_ids | Comma-separated list of alert IDs. | Optional | 
| limit | Limit number of records. | Optional | 
| permission_type | Permissions type. | Optional | 
| page_token | Next page token. | Optional | 
| prisma_cloud_findings_only | Filter Hyperion findings. Possible values are: true, false. | Optional | 
| vulnerability_info_type_id | CVE ID, package ID, or layer ID. The value needs to be fetched from one of the group by API calls. | Optional | 
| vulnerability_info_type | Supported vulnerability types. Possible values are: CVE, PACKAGE, LAYER. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloud.AssetRelationships.assetId | String | The asset ID of the asset relationship. | 
| PrismaCloud.AssetRelationships.relationshipType | String | The relationship type of the asset relationship. | 
| PrismaCloud.AssetRelationships.assetTypeId | Number | The asset type ID of the asset relationship. | 
| PrismaCloud.AssetRelationships.assetType | String | The asset type of the asset relationship. | 
| PrismaCloud.AssetRelationships.assetName | String | The asset name of the asset relationship. | 
| PrismaCloud.AssetRelationships.externalAssetId | String | The external asset ID of the asset relationship. | 
| PrismaCloud.AssetRelationships.cloudId | String | The cloud ID of the asset relationship. | 
| PrismaCloud.AssetRelationships.cloudName | String | The cloud name of the asset relationship. | 
| PrismaCloud.AssetRelationships.pseudoAsset | Boolean | The pseudo asset of the asset relationship. | 
| PrismaCloud.AssetRelationships.region | String | The region of the asset relationship. | 
| PrismaCloud.AssetRelationships.cloudAccountId | String | The cloud account ID of the asset relationship. | 
| PrismaCloud.AssetRelationships.assetClassId | String | The asset class ID of the asset relationship. | 
| PrismaCloud.AssetRelationships.assetClass | String | The asset class of the asset relationship. | 
| PrismaCloud.AssetRelationships.alertsCount.severity | String | The severity of the alerts of the asset relationship. | 
| PrismaCloud.AssetRelationships.alertsCount.count | Number | The number of alerts of the asset relationships. | 
| PrismaCloud.AssetRelationships.alertCountBySeverity.severity | String | The severity of the alerts of the asset relationship. | 
| PrismaCloud.AssetRelationships.alertCountBySeverity.count | Number | The number of alerts by severity of the asset relationship. | 
| PrismaCloud.AssetRelationships.vulnerabilityCounts | Unknown | The number of vulnerabilities of the asset relationship. | 
| PrismaCloud.AssetRelationships.problem.title | String | The title of the problem. | 
| PrismaCloud.AssetRelationships.problem.status.statusCode | Number | The status code of the problem. | 
| PrismaCloud.AssetRelationships.problem.status.reasonPhrase | String | The reason for the problem. | 
| PrismaCloud.AssetRelationships.problem.detail | String | The details of the problem. | 
| PrismaCloud.AssetRelationships.problem.instance | String | The instance of the problem. | 
| PrismaCloud.AssetRelationships.problem.type | String | The type of the problem. | 
| PrismaCloud.AssetRelationships.problem.parameters | Unknown | The parameters of the problem. | 

