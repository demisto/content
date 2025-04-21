Manage suspicious activities, monitoring alerts and entities on Microsoft ATA.

This integration was integrated and tested with version 1.9.7478.57683 of Microsoft Advanced Threat Analytics.

## Configure Microsoft Advanced Threat Analytics in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | ATA Center URL \(e.g. https://atacenter.contoso.com\) | True |
| credentials | Username | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| activity_status | Fetch suspicious activity with status | False |
| activity_type | Fetch suspicious activity with type \(leave empty to fetch all\) | False |
| min_severity | Minimum severity of suspicious activity to fetch | True |
| first_fetch | First fetch time range \(&lt;number&gt; &lt;time unit&gt;, e.g., 1 hour, 30 minutes\) | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ms-ata-suspicious-activities-list

***
Retrieves suspicious activities.


#### Base Command

`ms-ata-suspicious-activities-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Identifier of suspicious activity to retrieve (if provided, all other arguments will be ignored). | Optional | 
| status | Retrieve suspicious activities with the specified status (comma-seperated values suuported). | Optional | 
| severity | Retrieve suspicious activities with the specified severity (comma-seperated values suuported). | Optional | 
| type | Retrieve suspicious activities of the specified type (comma-seperated values suuported). | Optional | 
| limit | The maximum number of suspicious activities to retrieve. | Optional | 
| start_time | Retrieve suspicious activities which occurred after the given time. Supported formats: ISO 8601 (e.g. 2020-07-28T10:00:00Z) and time period (e.g. 24 hours).<br/> | Optional | 
| end_time | Retrieve suspicious activities which occurred before the given time. Supported formats: ISO 8601 (e.g. 2020-07-28T10:00:00Z) and time period (e.g. 24 hours). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATA.SuspiciousActivity.DescriptionDetailFormatKeys | String | List of detailed description of the suspicious acitivity format keys. | 
| MicrosoftATA.SuspiciousActivity.DescriptionFormatKey | String | Suspicious activity format key description. | 
| MicrosoftATA.SuspiciousActivity.DestinationComputerIds | String | List of identifiers of the destination computers. | 
| MicrosoftATA.SuspiciousActivity.EndTime | Date | End time of the suspicious activity. | 
| MicrosoftATA.SuspiciousActivity.ExclusionUniqueEntityId | String | Exclusion entity identifier of the suspicious activity. | 
| MicrosoftATA.SuspiciousActivity.HasDetails | Boolean | Whether the suspicious activity has further details to retrieve. | 
| MicrosoftATA.SuspiciousActivity.HasUnknownLdapResources | Boolean | Whether the suspicious activity has unknown LDAP resources. | 
| MicrosoftATA.SuspiciousActivity.HasUnknownNtlmResources | Boolean | Whether the suspicious activity has unknown NTLM resources. | 
| MicrosoftATA.SuspiciousActivity.HoneytokenAccountId | String | Account identifier of the Honeytoken suspicious activity. | 
| MicrosoftATA.SuspiciousActivity.Id | String | Identifier of the suspicious activity. | 
| MicrosoftATA.SuspiciousActivity.IsAdditionalDataAvailable | Boolean | Whether the suspicious activity has additional data available. | 
| MicrosoftATA.SuspiciousActivity.NtlmDestinationComputerIds | String | List of identifiers of the NTLM destination computers. | 
| MicrosoftATA.SuspiciousActivity.NtlmSourceComputerIds | String | List of identifiers of the NTLM source computers. | 
| MicrosoftATA.SuspiciousActivity.ReasonKey | String | The suspicious activity reason key. | 
| MicrosoftATA.SuspiciousActivity.RelatedActivityCount | Boolean | Count of related suspicious activities. | 
| MicrosoftATA.SuspiciousActivity.RelatedUniqueEntityIds | String | Exclusion entity identifier of related suspicious activities. | 
| MicrosoftATA.SuspiciousActivity.Severity | String | Severity of the suspicious activity. | 
| MicrosoftATA.SuspiciousActivity.SourceComputerIds | String | List of identifiers of the source computers. | 
| MicrosoftATA.SuspiciousActivity.StartTime | Date | Start time of the suspicious activity. | 
| MicrosoftATA.SuspiciousActivity.Status | String | Status of the suspicious activity. | 
| MicrosoftATA.SuspiciousActivity.StatusUpdateTime | Date | Time in which the suspicious activity status was updated in. | 
| MicrosoftATA.SuspiciousActivity.SystemCreationTime | Date | Time in which the suspicious activity was created in. | 
| MicrosoftATA.SuspiciousActivity.SystemUpdateTime | Date | Time in which the suspicious activity was updated in. | 
| MicrosoftATA.SuspiciousActivity.TitleKey | String | The suspicious activity title key. | 
| MicrosoftATA.SuspiciousActivity.Type | String | Type of the suspicious activity. | 
| MicrosoftATA.SuspiciousActivity.WindowsEventId | Boolean | Identifier of the suspicious activity windows event. | 
| MicrosoftATA.SuspiciousActivity.DetailsRecords.IsLogin | Boolean | Whether the suspicious activity indicates a login. | 
| MicrosoftATA.SuspiciousActivity.DetailsRecords.IsSuccess | Boolean | Whether the suspicious activity was successful. | 
| MicrosoftATA.SuspiciousActivity.DetailsRecords.IsTraffic | Boolean | Whether the suspicious activity indicates a traffic. | 
| MicrosoftATA.SuspiciousActivity.DetailsRecords.ProtocolName | String | Protocol of the suspicious activity. | 
| MicrosoftATA.SuspiciousActivity.DetailsRecords.ResourceIdentifier | String | Identifier of the suspicious activity source. | 
| MicrosoftATA.SuspiciousActivity.DetailsRecords.SourceComputerId | String | Identifier of the suspicious activity source computer. | 


#### Command Example

```!ms-ata-suspicious-activities-list```

#### Context Example

```
{
    "MicrosoftATA": {
        "SuspiciousActivity": {
            "DescriptionDetailFormatKeys": [
                "HoneytokenActivitySuspiciousActivityDescriptionDetailNtlmUnknownResourcesSuccess"
            ],
            "DescriptionFormatKey": "HoneytokenActivitySuspiciousActivityDescription",
            "DestinationComputerIds": [
                "6b0e48f5-6c63-449c-8b6f-c749e18e28b3"
            ],
            "EndTime": "2020-07-28T08:51:09.7050476Z",
            "EvidenceKeys": [],
            "ExclusionUniqueEntityId": null,
            "HasDetails": true,
            "HasUnknownLdapResources": false,
            "HasUnknownNtlmResources": true,
            "HoneytokenAccountId": "7a58c171-fa19-44f9-bf1e-81b544b318ad",
            "Id": "5f1fe6b383eaed101ce19b58",
            "IsAdditionalDataAvailable": false,
            "KerberosLoginDestinationComputerIds": [],
            "KerberosLoginSourceComputerIds": [],
            "KerberosResourceAccessDestinationComputerIds": [],
            "KerberosResourceAccessResourceIdentifiers": [],
            "KerberosResourceAccessSourceComputerIds": [],
            "LdapDestinationComputerIds": [],
            "LdapResourceIdentifiers": [],
            "LdapSourceComputerIds": [],
            "NtlmDestinationComputerIds": [
                "6b0e48f5-6c63-449c-8b6f-c749e18e28b3"
            ],
            "NtlmResourceIdentifiers": [],
            "NtlmSourceComputerIds": [
                "computer  ec2-1.eu.compute-1.amazonaws.com"
            ],
            "ReasonKey": "HoneytokenActivitySuspiciousActivityReason",
            "RelatedActivityCount": 3,
            "RelatedUniqueEntityIds": [
                "7a58c171-fa19-44f9-bf1e-81b544b318ad",
                "computer  ec2-3.eu.compute-1.amazonaws.com"
            ],
            "Severity": "Medium",
            "SourceComputerIds": [
                "computer  ec2-1.eu.compute-1.amazonaws.com"
            ],
            "SourceIpAddresses": [],
            "StartTime": "2020-07-28T08:49:54.1366697Z",
            "Status": "Open",
            "StatusUpdateTime": "2020-08-08T09:01:09.3438227Z",
            "SystemCreationTime": "2020-07-28T08:49:55.3139871Z",
            "SystemUpdateTime": "2020-08-08T09:01:09.3438227Z",
            "TitleKey": "HoneytokenActivitySuspiciousActivityTitle",
            "Type": "HoneytokenActivitySuspiciousActivity",
            "WindowsEventId": 2014
        }
    }
}
```

#### Human Readable Output

>### Microsoft Advanced Threat Analytics Suspicious Activity

>|Id|Type|Status|Severity|StartTime|EndTime|
>|---|---|---|---|---|---|
>| 5f1fe6b383eaed101ce19b58 | HoneytokenActivitySuspiciousActivity | Open | Medium | 2020-07-28T08:49:54.1366697Z | 2020-07-28T08:51:09.7050476Z |


### ms-ata-suspicious-activity-status-set

***
Sets suspicious activity status.


#### Base Command

`ms-ata-suspicious-activity-status-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Identifier of suspicious activity to update status of. | Required | 
| status | Status to update to | Required | 


#### Context Output

There is no context output for this command.

#### Command Example

```!ms-ata-suspicious-activity-status-set id="5f1fe6b383eaed101ce19b58" status="Closed"```

#### Human Readable Output

>Suspicious activity 5f1fe6b383eaed101ce19b58 status was updated to Closed successfully.

### ms-ata-monitoring-alerts-list

***
Retrieves health alerts.


#### Base Command

`ms-ata-monitoring-alerts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Retrieve monitoring alerts with the specified status (comma-seperated values suuported). | Optional | 
| severity | Retrieve monitoring alerts with the specified severity (comma-seperated values suuported). | Optional | 
| type | Retrieve monitoring alerts of the specified type (comma-seperated values suuported). | Optional | 
| limit | The maximum number of monitoring alerts to retrieve. | Optional | 
| start_time | Retrieve monitoring alerts which occurred after the given time. Supported formats: ISO 8601 (e.g. 2020-07-28T10:00:00Z) and time period (e.g. 24 hours).<br/> | Optional | 
| end_time | Retrieve monitoring alerts which occurred before the given time. Supported formats: ISO 8601 (e.g. 2020-07-28T10:00:00Z) and time period (e.g. 24 hours). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATA.MonitoringAlert.DescriptionFormatKey | String | Monitoring alert format key description. | 
| MicrosoftATA.MonitoringAlert.DomainSynchronizerNotAssignedDomainDnsNames | String | Monitoring alert domain synchronizer not assigned domain DNS names. | 
| MicrosoftATA.MonitoringAlert.EndTime | Date | End time of the monitoring alert. | 
| MicrosoftATA.MonitoringAlert.Id | String | Identifier of the monitoring alert. | 
| MicrosoftATA.MonitoringAlert.NotificationTime | Date | Notification time of the monitoring alert. | 
| MicrosoftATA.MonitoringAlert.Severity | String | Severity of the monitoring alert. | 
| MicrosoftATA.MonitoringAlert.StartTime | Date | Start time of the monitoring alert. | 
| MicrosoftATA.MonitoringAlert.Status | String | Status of the monitoring alert. | 
| MicrosoftATA.MonitoringAlert.StatusUpdateTime | Date | Status update time of the monitoring alert. | 
| MicrosoftATA.MonitoringAlert.TitleKey | String | The monitoring alert title key. | 
| MicrosoftATA.MonitoringAlert.Type | String | Type of the monitoring alert. | 
| MicrosoftATA.MonitoringAlert.WindowsEventId | Boolean | Identifier of the monitoring alert windows event. | 
| MicrosoftATA.MonitoringAlert.AccountDomainName | String | Monitoring alert account domain name. | 
| MicrosoftATA.MonitoringAlert.AccountName | String | Monitoring alert account name. | 
| MicrosoftATA.MonitoringAlert.IsPasswordExpired | Boolean | Whether the monitoring alert indicates that password has expired. | 
| MicrosoftATA.MonitoringAlert.PasswordExpiryTime | Date | Password expiry time. | 


#### Command Example

```!ms-ata-monitoring-alerts-list```

#### Context Example

```
{
    "MicrosoftATA": {
        "MonitoringAlert": [
            {
                "DescriptionDetailFormatKeys": [],
                "DescriptionFormatKey": "GatewayDomainSynchronizerNotAssignedMonitoringAlertDescription",
                "DomainSynchronizerNotAssignedDomainDnsNames": [
                    "demisto.local"
                ],
                "EndTime": "2020-07-28T11:17:28.6742502Z",
                "Id": "5f159bbd83eaed101cd5c4e5",
                "NotificationTime": "2020-07-20T13:27:25.8510125Z",
                "Severity": "Low",
                "StartTime": "2020-07-20T13:27:25.7800034Z",
                "Status": "Closed",
                "StatusUpdateTime": "2020-07-28T11:17:28.6742502Z",
                "TitleKey": "GatewayDomainSynchronizerNotAssignedMonitoringAlertTitle",
                "Type": "GatewayDomainSynchronizerNotAssignedMonitoringAlert",
                "WindowsEventId": 1007
            },
            {
                "AccountDomainName": "demisto",
                "AccountName": "Administrator",
                "DescriptionDetailFormatKeys": [],
                "DescriptionFormatKey": "GatewayDirectoryServicesClientAccountPasswordExpiryMonitoringAlertDescriptionNearExpiry",
                "EndTime": "2020-07-28T12:06:30.9408859Z",
                "Id": "5f159e9283eaed101cd5c837",
                "IsPasswordExpired": false,
                "NotificationTime": "2020-07-20T13:39:30.5978881Z",
                "PasswordExpiryTime": "2020-08-17T13:01:15.1609716Z",
                "Severity": "Medium",
                "StartTime": "2020-07-20T13:39:30.5559003Z",
                "Status": "Closed",
                "StatusUpdateTime": "2020-07-28T12:06:30.9408859Z",
                "TitleKey": "GatewayDirectoryServicesClientAccountPasswordExpiryMonitoringAlertTitleNearExpiry",
                "Type": "GatewayDirectoryServicesClientAccountPasswordExpiryMonitoringAlert",
                "WindowsEventId": 1006
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft Advanced Threat Analytics Monitoring Alert

>|Id|Type|Status|Severity|StartTime|EndTime|
>|---|---|---|---|---|---|
>| 5f159bbd83eaed101cd5c4e5 | GatewayDomainSynchronizerNotAssignedMonitoringAlert | Closed | Low | 2020-07-20T13:27:25.7800034Z | 2020-07-28T11:17:28.6742502Z |
>| 5f159e9283eaed101cd5c837 | GatewayDirectoryServicesClientAccountPasswordExpiryMonitoringAlert | Closed | Medium | 2020-07-20T13:39:30.5559003Z | 2020-07-28T12:06:30.9408859Z |


### ms-ata-entity-get

***
Retrieves information of distinct entity, such as computers and users.


#### Base Command

`ms-ata-entity-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Identifier of distinct entity to retrieve (Can be retrieved by running the command ms-ata-suspicious-activities-list from the output RelatedUniqueEntityIds). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftATA.Entity.BadPasswordTime | Date | Time in which bad password was entered. | 
| MicrosoftATA.Entity.CanonicalName | String | Entity canonical name. | 
| MicrosoftATA.Entity.CreationTime | Date | Time in which the entity was created in. | 
| MicrosoftATA.Entity.Description | String | Entity description. | 
| MicrosoftATA.Entity.DistinguishedName | String | Entity distinguished name. | 
| MicrosoftATA.Entity.DnsName | String | Entity DNS name. | 
| MicrosoftATA.Entity.DomainController.IsGlobalCatalog | Boolean | Whether the entity is in the global catalog. | 
| MicrosoftATA.Entity.DomainController.IsPrimary | Boolean | Whether the entity is primary. | 
| MicrosoftATA.Entity.DomainController.IsReadOnly | Boolean | Whether the entity is read only. | 
| MicrosoftATA.Entity.DomainId | String | Identifier of the entity domain. | 
| MicrosoftATA.Entity.ExpiryTime | Date | Expiration time of the entity. | 
| MicrosoftATA.Entity.Id | String | Identifer of the entity. | 
| MicrosoftATA.Entity.IpAddress | String | Entity IP address. | 
| MicrosoftATA.Entity.IsDelegationEnabled | Boolean | Whether the entity is delegation enabled. | 
| MicrosoftATA.Entity.IsDeleted | Boolean | Whether the entity is deleted. | 
| MicrosoftATA.Entity.IsDesEncryptionOnly | Boolean | Whether the entity is Data Encryption Standard only. | 
| MicrosoftATA.Entity.IsDisabled | Boolean | Whether the entity is disabled. | 
| MicrosoftATA.Entity.IsDomainController | Boolean | Whether the entity is domain controller. | 
| MicrosoftATA.Entity.IsExpired | Boolean | Whether the entity is expired. | 
| MicrosoftATA.Entity.IsHoneytoken | Boolean | Whether the entity is related to Honeytoken activity. | 
| MicrosoftATA.Entity.IsLocked | Boolean | Whether the entity is locked. | 
| MicrosoftATA.Entity.IsNew | Boolean | Whether the entity is new. | 
| MicrosoftATA.Entity.IsNotDelegatable | Boolean | Whether the entity is non\-delegatable. | 
| MicrosoftATA.Entity.IsPartial | Boolean | Whether the entity is partial. | 
| MicrosoftATA.Entity.IsPasswordExpired | Boolean | Whether the entity password is expired. | 
| MicrosoftATA.Entity.IsSensitive | Boolean | Whether the entity is sensitive. | 
| MicrosoftATA.Entity.IsServer | Boolean | Whether the entity is a server. | 
| MicrosoftATA.Entity.IsSmartcardRequired | Boolean | Whether a smart card is required for the entity. | 
| MicrosoftATA.Entity.OperatingSystemDisplayName | String | The entity OS name, | 
| MicrosoftATA.Entity.SamName | String | Entitiy Security Account Manager name. | 
| MicrosoftATA.Entity.Sid | String | Entity security identifier. | 
| MicrosoftATA.Entity.Spns | String | Entity Search Service Principal Names. | 
| MicrosoftATA.Entity.SystemCreationTime | Date | System creation time of the entity. | 
| MicrosoftATA.Entity.SystemDisplayName | String | System display name of the entity. | 
| MicrosoftATA.Entity.Type | String | Type of the entity. | 
| MicrosoftATA.Entity.UpnName | String | Entity User Principal Name. | 
| MicrosoftATA.Entity.Profile.IsBehaviorChanged | Boolean | Whether the entity profile behavior changed. | 
| MicrosoftATA.Entity.Profile.OpenSuspiciousActivityCount | Boolean | Number of entity profile suspicious activities. | 
| MicrosoftATA.Entity.Profile.SuspiciousActivitySeverityToCountMapping.High | Number | Number of entity profile suspicious activities with High severity. | 
| MicrosoftATA.Entity.Profile.SuspiciousActivitySeverityToCountMapping.Low | Number | Number of entity profile suspicious activities with Low severity. | 
| MicrosoftATA.Entity.Profile.SuspiciousActivitySeverityToCountMapping.Medium | Number | Number of entity profile suspicious activities with Medium severity. | 
| MicrosoftATA.Entity.Profile.Type | String | Type of the entity profile. | 
| MicrosoftATA.Entity.Profile.UpdateTime | Date | Update time of the entity profile. | 


#### Command Example

```!ms-ata-entity-get id="7a58c171-fa19-44f9-bf1e-81b544b318ad"```

#### Context Example

```
{
    "MicrosoftATA": {
        "Entity": {
            "BadPasswordTime": null,
            "CanonicalName": "demisto.local/Users/Test ATA",
            "ConstrainedDelegationSpns": [],
            "CreationTime": "2020-07-21T13:58:11Z",
            "Department": null,
            "Description": null,
            "DistinguishedName": "CN=Test ATA,CN=Users,DC=demisto,DC=local",
            "DomainId": "3ae90e0d-eb20-4a4c-a922-0606ab7ae307",
            "ExpiryTime": null,
            "HasPhoto": false,
            "Id": "7a58c171-fa19-44f9-bf1e-81b544b318ad",
            "IsDelegationEnabled": false,
            "IsDeleted": false,
            "IsDesEncryptionOnly": false,
            "IsDisabled": false,
            "IsExpired": false,
            "IsHoneytoken": true,
            "IsLocked": false,
            "IsNew": true,
            "IsNotDelegatable": false,
            "IsPartial": false,
            "IsPasswordExpired": false,
            "IsPasswordFarExpiry": false,
            "IsPasswordNeverExpires": true,
            "IsPasswordNotRequired": false,
            "IsPlaintextPasswordAllowed": false,
            "IsPreauthenticationNotRequired": false,
            "IsSensitive": false,
            "IsSmartcardRequired": false,
            "IsTaggedAsSensitive": false,
            "Mail": null,
            "MobileNumber": null,
            "Office": null,
            "PasswordExpiryTime": null,
            "PasswordUpdateTime": "2020-07-21T13:58:11.4101455Z",
            "PhoneNumber": null,
            "Profile": {
                "AccessedResourceAccountIdToTimeMapping": {},
                "DateToPrivilegeEscalationPathsMapping": {},
                "DateToSourceComputerIdToProtocolToCertaintyMapping": {
                    "2020-07-21T00:00:00Z": {
                        "6b0e48f5-6c63-449c-8b6f-c749e18e28b3": {
                            "NtlmEvent": "High"
                        }
                    },
                    "2020-07-22T00:00:00Z": {
                        "6b0e48f5-6c63-449c-8b6f-c749e18e28b3": {
                            "NtlmEvent": "High"
                        },
                        "computer  ec2-1.eu.compute-1.amazonaws.com": {
                            "NtlmEvent": "High"
                        }
                    },
                    "2020-07-28T00:00:00Z": {
                        "computer  ec2-1.eu.compute-1.amazonaws.com": {
                            "NtlmEvent": "High"
                        }
                    }
                },
                "GeolocationIdToTimeMapping": {},
                "Id": "7a58c171-fa19-44f9-bf1e-81b544b318ad",
                "IsBehaviorChanged": true,
                "LogonComputerIdToTimeMapping": {},
                "OpenSuspiciousActivityCount": 0,
                "SuspiciousActivitySeverityToCountMapping": {
                    "High": 0,
                    "Low": 0,
                    "Medium": 0
                },
                "Type": "UserProfile",
                "UpdateTime": "2020-07-28T09:00:13.8696377Z"
            },
            "SamName": "testata",
            "SensitiveRootParentGroupIds": [],
            "SensitivityReasonFormatKeys": [],
            "Sid": "S-1-5-21-1234499873-1172443441-1549941920-1115",
            "Spns": [],
            "SystemCreationTime": "2020-07-21T14:00:07.5795659Z",
            "SystemDisplayName": "Test ATA",
            "SystemSubDisplayName": null,
            "Title": null,
            "Type": "User",
            "UpnName": "testata@demisto.local"
        }
    }
}
```

#### Human Readable Output

>### Microsoft Advanced Threat Analytics Entity 7a58c171-fa19-44f9-bf1e-81b544b318ad

>|Id|SystemDisplayName|DistinguishedName|UpnName|Type|CreationTime|
>|---|---|---|---|---|---|
>| 7a58c171-fa19-44f9-bf1e-81b544b318ad | Test ATA | CN=Test ATA,CN=Users,DC=demisto,DC=local | testata@demisto.local | User | 2020-07-21T13:58:11Z |

>### Entity Profile

>|Type|SuspiciousActivitySeverityToCountMapping|UpdateTime|IsBehaviorChanged|
>|---|---|---|---|
>| UserProfile | Low: 0<br/>Medium: 0<br/>High: 0 | 2020-07-28T09:00:13.8696377Z | true |
