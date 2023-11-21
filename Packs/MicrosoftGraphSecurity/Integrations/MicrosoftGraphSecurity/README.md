Unified gateway to security insights - all from a unified Microsoft Graph Security API.
This integration was integrated and tested with version 1.0 of Microsoft Graph.

## Authentication

For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication)
Note: eDiscovery commands only support the `Delegated (work or school account)` permission type.

## Important Notes:
- Due to API limitations, the ***message-search-alerts*** command does not filter Office 365 provider alerts.\
For more information, see: https://github.com/microsoftgraph/security-api-solutions/issues/56.
- When using Alerts V2, only the following properties are supported as filters for the *Fetched incidents filter* parameter and *filter* arguments: assignedTo, classification, determination, createdDateTime, lastUpdateDateTime, severity, serviceSource and status. See [Microsoft optional query parameters](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0&tabs=http#optional-query-parameters).
- As of July 2023, Microsoft Graph API does **not support** a solution to search for and delete emails. To do this, refer to the [Security & Compliance](https://xsoar.pan.dev/docs/reference/integrations/security-and-compliance) integration. 

### Required Permissions

Legacy Alerts:

1. SecurityEvents.Read.All - Application (required for the commands: `msg-search-alerts` and `msg-get-alert-details`)
2. SecurityEvents.ReadWrite.All - Application (required for updating alerts with the command: `msg-update-alert`)
3. User.Read.All - Application (Only required if using the deprecated commands: `msg-get-user` and `msg-get-users`)

Alerts v2:

1. SecurityAlert.Read.All - Application (required for the commands: `msg-search-alerts` and `msg-get-alert-details`)
2. SecurityAlert.ReadWrite.All - Application (required for updating alerts with the commands: `msg-update-alert` and `msg-create-alert-comment`)

EDiscovery:

1. eDiscovery.Read.All - Delegated (Required for the `list-ediscovery` commands)
2. eDiscovery.ReadWrite.All - Delegated (Required for the `create/update-ediscovery` commands)

## Configure Microsoft Graph Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Graph Security.
3. Click **Add instance** to create and configure a new integration instance.

     | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Host URL | The host URL. | True |
    | MS graph security version | MS graph security API version. | True |
    | Application ID or Client ID | The app registration ID. | True |
    | Token or Tenant ID | The tenant ID. | True |
    | Key or Client Secret | The app registration secret. | False |
    | Authorization code | Get the authorization code from steps 3-5 in the self deployed authorization process.| False |
    | Application redirect URI (for self-deployed mode) | The app registration redirect URI. | False |
    | Certificate Thumbprint | Used for certificate authentication, as it appears in the "Certificates & secrets" page of the app. | False |
    | Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
    | Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
    | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
    | Trust any certificate (not secure) | Whether to trust any certificate. If True, not secure. | False |
    | Use system proxy settings | Whether to use system proxy settings. | False |
    | Use a self-deployed Azure application | Whether to use a self-deployed application. | False |
    | Fetch incidents | Whether to fetch incidents. | False |
    | Incident type | The incident type to apply. | False |
    | First fetch timestamp (`<number> <time unit>`, e.g., 12 hours, 7 days) | `<number> <time unit>`, for example 1 hour, 30 minutes. | False |
    | Max incidents per fetch | The maximum number of incidents to fetch per iteration. | False |
    | Fetch incidents of the given providers only. | Relevant only for Legacy Alerts. Multiple providers can be inserted separated by a comma, for example "\{first_provider\},\{second_provider\}". If empty, incidents of all providers will be fetched. | False |
    | Fetch incidents of the given service sources only. | Relevant only for Alerts v2. Multiple serviceSource can be inserted separated by a comma, for example "microsoftDefenderForEndpoint,microsoftCloudAppSecurity",. If empty, incidents of all providers will be fetched. | False |
    | Fetched incidents filter | Use this field to filter fetched incidents according to any of the alert properties. Overrides the providers list, if given. Filter should be in the format "\{property\} eq '\{property-value\}'". Multiple filters can be applied separated with " and ", for example "createdDateTime eq YYYY-MM-DD and severity eq 'high'". | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msg-auth-test

***
Tests connectivity to Microsoft Graph Security.

#### Base Command

`msg-auth-test`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| permission_type | Which permissions the integration should have. Possible values are: ediscovery, alerts, alerts, ediscovery. Default is ediscovery. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-auth-test permission_type=ediscovery```

#### Human Readable Output

>Authentication was successful.

### msg-search-alerts

***
List alerts (security issues) within a customer's tenant that Microsoft or partner security solutions have identified.

#### Base Command

`msg-search-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_modified | When the alert was last modified in the following string format - YYYY-MM-DD. Possible values are: Last24Hours, Last48Hours, LastWeek. | Optional | 
| severity | Alert severity - set by vendor/provider. Possible values are: unknown, informational, low, medium, high. | Optional | 
| category | Category of the alert, e.g., credentialTheft, ransomware (Categories can be added or removed by vendors.). | Optional | 
| time_from | The start time (creation time of alert) for the search in the following string format - YYYY-MM-DD. | Optional | 
| time_to | The end time (creation time of alert) for the search in the following string format -  YYYY-MM-DD. | Optional | 
| filter | Use this field to filter on any of the alert properties in the format "{property} eq '{property-value}'", e.g. "category eq 'ransomware'". | Optional | 
| classification | Relevant only for Alerts v2. Use this field to filter by alert's classification. Possible values are: unknown, truePositive, falsePositive, benignPositive. | Optional | 
| service_source | Relevant only for Alerts v2. Use this field to filter the alerts by the service or product that created this alert. Possible values are: microsoftDefenderForEndpoint, microsoftDefenderForIdentity, microsoftDefenderForOffice365, microsoft365Defender, microsoftAppGovernance, microsoftDefenderForCloudApps. | Optional | 
| status | Relevant only for Alerts v2. Use this field to filter by alert's status. Possible values are: unknown, new, inProgress, resolved. | Optional | 
| page | Page number to return, zero indexed. The maximum number of alerts that can be skipped for Legacy Alerts is 500 (i.e., page * page_size must be &lt;= 500). | Optional | 
| page_size | Number of results in a page. Default is 50, the limit for Legacy Alerts is 1000, the limit for Alerts v2 is 2000. When using Legacy Alerts, the response will provide <page_size> results for each provider. | Optional | 
| limit | Number of total results to return. Default is 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Alert.ID | string | Alert ID. | 
| MsGraph.Alert.Title | string | Alert title. | 
| MsGraph.Alert.Category | string | Alert category. | 
| MsGraph.Alert.Severity | string | Alert severity. | 
| MsGraph.Alert.CreatedDate | date | Alert created date. | 
| MsGraph.Alert.EventDate | date | Relevant only for Legacy Alerts. Alert event time. | 
| MsGraph.Alert.Status | string | Alert status. | 
| MsGraph.Alert.Vendor | string | Relevant only for Legacy Alerts. Alert vendor. | 
| MsGraph.Alert.MalwareStates | string | Relevant only for Legacy Alerts. Alert malware states. |
| MsGraph.Alert.Provider | string | Relevant only for Legacy Alerts. Alert provider. | 
| MsGraph.Alert.ActorDisplayName | Unknown | Relevant only for Alerts v2. Alert actor name. | 
| MsGraph.Alert.AlertWebUrl | String | Relevant only for Alerts v2. Alert web URL. | 
| MsGraph.Alert.AssignedTo | Unknown | Relevant only for Alerts v2. Alert assignee. | 
| MsGraph.Alert.Classification | Unknown | Relevant only for Alerts v2. Alert classification. | 
| MsGraph.Alert.Description | String | Relevant only for Alerts v2. Alert description. | 
| MsGraph.Alert.DetectionSource | String | Relevant only for Alerts v2. Alert detection source. | 
| MsGraph.Alert.DetectorId | String | Relevant only for Alerts v2. Alert detector ID. | 
| MsGraph.Alert.Determination | Unknown | Relevant only for Alerts v2. Alert determination. | 
| MsGraph.Alert.Evidence.@odata.Type | String | Relevant only for Alerts v2. Alert evidence. | 
| MsGraph.Alert.Evidence.AzureAdDeviceId | String | Relevant only for Alerts v2. Evidence Azure device ID. | 
| MsGraph.Alert.Evidence.CreatedDate | Date | Relevant only for Alerts v2. Evidence creation time. | 
| MsGraph.Alert.Evidence.DefenderAvStatus | String | Relevant only for Alerts v2. Evidence Defender AV status. | 
| MsGraph.Alert.Evidence.DeviceDnsName | String | Relevant only for Alerts v2. Evidence device DNS name. | 
| MsGraph.Alert.Evidence.FirstSeenDateTime | Date | Relevant only for Alerts v2. Evidence first seen time. | 
| MsGraph.Alert.Evidence.HealthStatus | String | Relevant only for Alerts v2. Evidence health status. | 
| MsGraph.Alert.Evidence.MdeDeviceId | String | Relevant only for Alerts v2. Evidence MDE device ID. | 
| MsGraph.Alert.Evidence.OnboardingStatus | String | Relevant only for Alerts v2. Evidence onboarding status. | 
| MsGraph.Alert.Evidence.OsBuild | Number | Relevant only for Alerts v2. Evidence OS build. | 
| MsGraph.Alert.Evidence.OsPlatform | String | Relevant only for Alerts v2. Evidence OS platform. | 
| MsGraph.Alert.Evidence.RbacGroupId | Number | Relevant only for Alerts v2. Evidence RBAC group ID. | 
| MsGraph.Alert.Evidence.RbacGroupName | String | Relevant only for Alerts v2. Evidence RBAC group name. | 
| MsGraph.Alert.Evidence.RemediationStatus | String | Relevant only for Alerts v2. Evidence remediation status. | 
| MsGraph.Alert.Evidence.RemediationStatusDetails | Unknown | Relevant only for Alerts v2. Evidence remediation status details. | 
| MsGraph.Alert.Evidence.RiskScore | String | Relevant only for Alerts v2. Evidence risk score. | 
| MsGraph.Alert.Evidence.Tags | String | Relevant only for Alerts v2. Evidence tags. | 
| MsGraph.Alert.Evidence.Verdict | String | Relevant only for Alerts v2. Evidence verdict. | 
| MsGraph.Alert.Evidence.Version | String | Relevant only for Alerts v2. Evidence version. | 
| MsGraph.Alert.Evidence.VmMetadata | Unknown | Relevant only for Alerts v2. Evidence VM metadata. | 
| MsGraph.Alert.FirstActivityDateTime | Date | Relevant only for Alerts v2. Evidence first activity time. | 
| MsGraph.Alert.IncidentId | String | Relevant only for Alerts v2. Alert incident ID. | 
| MsGraph.Alert.IncidentWebUrl | String | Relevant only for Alerts v2. Alert incident URL. | 
| MsGraph.Alert.LastActivityDateTime | Date | Relevant only for Alerts v2. Alert last activity time. | 
| MsGraph.Alert.LastUpdateDateTime | Date | Relevant only for Alerts v2. Alert last update time. | 
| MsGraph.Alert.ProviderAlertId | String | Relevant only for Alerts v2. Alert provider ID. | 
| MsGraph.Alert.RecommendedActions | String | Relevant only for Alerts v2. Alert recommended action. | 
| MsGraph.Alert.ResolvedDateTime | Date | Relevant only for Alerts v2. Alert closing time. | 
| MsGraph.Alert.ServiceSource | String | Relevant only for Alerts v2. Alert service source. | 
| MsGraph.Alert.TenantId | String | Relevant only for Alerts v2. Alert tenant ID. | 
| MsGraph.Alert.ThreatDisplayName | Unknown | Relevant only for Alerts v2. Alert threat display name. | 
| MsGraph.Alert.ThreatFamilyName | Unknown | Relevant only for Alerts v2. Alert threat family name. | 

#### Human Readable Output

>## Using Legacy Alerts:

>### Microsoft Security Graph Alerts

>|ID|Vendor|Provider|Title|Category|Severity|CreatedDate|EventDate|Status|
>|---|---|---|---|---|---|---|---|---|
>| id | Microsoft | IPC | Atypical travel | ImpossibleTravel | high | 2023-03-30T20:45:14.259Z | 2023-03-30T15:07:21.4705248Z | newAlert |

>## Using Alerts v2:

>### Microsoft Security Graph Alerts

>|ID|IncidentId|Status|Severity|DetectionSource|ServiceSource|Title|Category|CreatedDate|LastUpdateDateTime|
>|---|---|---|---|---|---|---|---|---|---|
>| id | <incident_id> | new | medium | customTi | microsoftDefenderForEndpoint | test alert | None | 2022-10-03T03:39:21.7562976Z | 2023-04-17T11:01:31.7566667Z |

### msg-get-alert-details

***
Get details for a specific alert.

#### Base Command

`msg-get-alert-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The alert ID - Provider-generated GUID/unique identifier. | Required | 
| fields_to_include | Relevant only for Legacy Alerts. Fields to fetch for a specified alert apart from the basic properties, given as comma separated values, e.g., NetworkConnections,Processes. The possible values are: All, NetworkConnections, Processes, RegistryKeys, UserStates, HostStates, FileStates, CloudAppStates, MalwareStates, CustomerComments, Triggers, VendorInformation, VulnerabilityStates. Default is All. | Optional |  

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Alert.ID | string | Alert ID. | 
| MsGraph.Alert.Title | string | Alert title. | 
| MsGraph.Alert.Category | string | Alert category. | 
| MsGraph.Alert.Severity | string | Alert severity. | 
| MsGraph.Alert.CreatedDate | date | Relevant only for Legacy Alerts. Alert created date. | 
| MsGraph.Alert.EventDate | date | Relevant only for Legacy Alerts. Alert event time. | 
| MsGraph.Alert.Status | string | Alert status. | 
| MsGraph.Alert.Vendor | string | Relevant only for Legacy Alerts. Alert vendor. | 
| MsGraph.Alert.Provider | string | Relevant only for Legacy Alerts. Alert provider. | 
| MsGraph.Alert.@odata.Context | String | Relevant only for Alerts v2. Alert odata context. | 
| MsGraph.Alert.ActorDisplayName | Unknown | Relevant only for Alerts v2. Alert actor name. | 
| MsGraph.Alert.AlertWebUrl | String | Relevant only for Alerts v2. Alert web URL. | 
| MsGraph.Alert.AssignedTo | Unknown | Relevant only for Alerts v2. Alert assignee. | 
| MsGraph.Alert.Classification | Unknown | Relevant only for Alerts v2. Alert classification. | 
| MsGraph.Alert.Comments.Comment | String | Relevant only for Alerts v2. Alert comment. | 
| MsGraph.Alert.Comments.CreatedByDisplayName | String | Relevant only for Alerts v2. Alert comment creator name. | 
| MsGraph.Alert.Comments.CreatedDate | Date | Relevant only for Alerts v2. Alert comment creation time. | 
| MsGraph.Alert.CreatedDate | Date | Relevant only for Alerts v2. Alert creation time. | 
| MsGraph.Alert.Description | String | Relevant only for Alerts v2. Alert description. | 
| MsGraph.Alert.DetectionSource | String | Relevant only for Alerts v2. Alert detection source. | 
| MsGraph.Alert.DetectorId | String | Relevant only for Alerts v2. Alert detector ID. | 
| MsGraph.Alert.Determination | Unknown | Relevant only for Alerts v2. Alert determination. | 
| MsGraph.Alert.Evidence.@odata.Type | String | Relevant only for Alerts v2. Alert evidence. | 
| MsGraph.Alert.Evidence.CreatedDate | Date | Relevant only for Alerts v2. Evidence creation time. | 
| MsGraph.Alert.Evidence.DetectionStatus | Unknown | Relevant only for Alerts v2. Evidence detection status. | 
| MsGraph.Alert.Evidence.ImageFile.FileName | String | Relevant only for Alerts v2. Evidence image file name. | 
| MsGraph.Alert.Evidence.ImageFile.FilePath | String | Relevant only for Alerts v2. Evidence image file path. | 
| MsGraph.Alert.Evidence.ImageFile.FilePublisher | Unknown | Relevant only for Alerts v2. Evidence image file publisher. | 
| MsGraph.Alert.Evidence.ImageFile.FileSize | Unknown | Relevant only for Alerts v2. Evidence image file size. | 
| MsGraph.Alert.Evidence.ImageFile.Issuer | Unknown | Relevant only for Alerts v2. Evidence image file issuer. | 
| MsGraph.Alert.Evidence.ImageFile.Sha1 | String | Relevant only for Alerts v2. Evidence image file SHA1 hash. | 
| MsGraph.Alert.Evidence.ImageFile.Sha256 | String | Relevant only for Alerts v2. Evidence image file SHA256 hash. | 
| MsGraph.Alert.Evidence.ImageFile.Signer | Unknown | Relevant only for Alerts v2. Evidence image file signer. | 
| MsGraph.Alert.Evidence.MdeDeviceId | Unknown | Relevant only for Alerts v2. Evidence MDE device ID. | 
| MsGraph.Alert.Evidence.ParentProcessCreationDateTime | Date | Relevant only for Alerts v2. Evidence parent process creation time. | 
| MsGraph.Alert.Evidence.ParentProcessId | Number | Relevant only for Alerts v2. Evidence parent process process ID. | 
| MsGraph.Alert.Evidence.ParentProcessImageFile | Unknown | Relevant only for Alerts v2. Evidence parent process image file. | 
| MsGraph.Alert.Evidence.ProcessCommandLine | String | Relevant only for Alerts v2. Evidence process command line. | 
| MsGraph.Alert.Evidence.ProcessCreationDateTime | Date | Relevant only for Alerts v2.  Evidence process creation time. | 
| MsGraph.Alert.Evidence.ProcessId | Number | Relevant only for Alerts v2.  Evidence process ID. | 
| MsGraph.Alert.Evidence.RemediationStatus | String | Relevant only for Alerts v2. Evidence remediation status. | 
| MsGraph.Alert.Evidence.RemediationStatusDetails | Unknown | Relevant only for Alerts v2. Evidence remediation status details. | 
| MsGraph.Alert.Evidence.UserAccount.AccountName | String | Relevant only for Alerts v2. Evidence user account name. | 
| MsGraph.Alert.Evidence.UserAccount.AzureAdUserId | Unknown | Relevant only for Alerts v2. Evidence user account Azure AD user ID. | 
| MsGraph.Alert.Evidence.UserAccount.DisplayName | String | Relevant only for Alerts v2. Evidence user account display name. | 
| MsGraph.Alert.Evidence.UserAccount.DomainName | Unknown | Relevant only for Alerts v2. Evidence user account domain name. | 
| MsGraph.Alert.Evidence.UserAccount.UserPrincipalName | Unknown | Relevant only for Alerts v2. Evidence user account user principal name. | 
| MsGraph.Alert.Evidence.UserAccount.UserSid | String | Relevant only for Alerts v2. Evidence user account user SID. | 
| MsGraph.Alert.Evidence.Verdict | String | Relevant only for Alerts v2. Evidence verdict. | 
| MsGraph.Alert.Evidence.FileDetails.FileName | String | Relevant only for Alerts v2. Evidence file details file name. | 
| MsGraph.Alert.Evidence.FileDetails.FilePath | String | Relevant only for Alerts v2. Evidence file details file path. | 
| MsGraph.Alert.Evidence.FileDetails.FilePublisher | Unknown | Relevant only for Alerts v2. Evidence file details file publisher. | 
| MsGraph.Alert.Evidence.FileDetails.FileSize | Unknown | Relevant only for Alerts v2. Evidence file details file size. | 
| MsGraph.Alert.Evidence.FileDetails.Issuer | Unknown | Relevant only for Alerts v2. Evidence file details file issuer. | 
| MsGraph.Alert.Evidence.FileDetails.Sha1 | String | Relevant only for Alerts v2. Evidence file details SHA1 hash. | 
| MsGraph.Alert.Evidence.FileDetails.Sha256 | String | Relevant only for Alerts v2. Evidence file details SHA256 hash. | 
| MsGraph.Alert.Evidence.FileDetails.Signer | Unknown | Relevant only for Alerts v2. Evidence file details file signer. | 
| MsGraph.Alert.Evidence.CֹountryLetterCode | Unknown | Relevant only for Alerts v2. Evidence country letter code. | 
| MsGraph.Alert.Evidence.IpAddress | String | Relevant only for Alerts v2. Evidence IP address. | 
| MsGraph.Alert.Evidence.AzureAdDeviceId | Unknown | Relevant only for Alerts v2. Evidence Azure AD device ID. | 
| MsGraph.Alert.Evidence.DefenderAvStatus | String | Relevant only for Alerts v2. Evidence Defender AV status. | 
| MsGraph.Alert.Evidence.DeviceDnsName | String | Relevant only for Alerts v2. Evidence device DNS name. | 
| MsGraph.Alert.Evidence.FirstSeenDateTime | Date | Relevant only for Alerts v2. Evidence first seen time. | 
| MsGraph.Alert.Evidence.HealthStatus | String | Relevant only for Alerts v2. Evidence health status. | 
| MsGraph.Alert.Evidence.OnboardingStatus | String | Relevant only for Alerts v2. Evidence onboarding status. | 
| MsGraph.Alert.Evidence.OsBuild | Unknown | Relevant only for Alerts v2. Evidence OS build. | 
| MsGraph.Alert.Evidence.OsPlatform | String | Relevant only for Alerts v2. Evidence OS platform. | 
| MsGraph.Alert.Evidence.RbacGroupId | Number | Relevant only for Alerts v2. Evidence RBAC group ID. | 
| MsGraph.Alert.Evidence.RbacGroupName | String | Relevant only for Alerts v2. Evidence RBAC group name. | 
| MsGraph.Alert.Evidence.RiskScore | String | Relevant only for Alerts v2. Evidence risk score. | 
| MsGraph.Alert.Evidence.Version | String | Relevant only for Alerts v2. Evidence version. | 
| MsGraph.Alert.Evidence.VmMetadata | Unknown | Relevant only for Alerts v2. Evidence VM metadata. | 
| MsGraph.Alert.FirstActivityDateTime | Date | Relevant only for Alerts v2. Evidence first activity time. | 
| MsGraph.Alert.IncidentId | String | Relevant only for Alerts v2. Alert incident ID. | 
| MsGraph.Alert.IncidentWebUrl | String | Relevant only for Alerts v2. Alert incident URL. | 
| MsGraph.Alert.LastActivityDateTime | Date | Relevant only for Alerts v2. Alert last activity time. | 
| MsGraph.Alert.LastUpdateDateTime | Date | Relevant only for Alerts v2. Alert last update time. | 
| MsGraph.Alert.ProviderAlertId | String | Relevant only for Alerts v2. Alert provider ID. | 
| MsGraph.Alert.RecommendedActions | String | Relevant only for Alerts v2. Alert recommended action. | 
| MsGraph.Alert.ResolvedDateTime | Date | Relevant only for Alerts v2. Alert closing time. | 
| MsGraph.Alert.ServiceSource | String | Relevant only for Alerts v2. Alert service source. | 
| MsGraph.Alert.TenantId | String | Relevant only for Alerts v2. Alert tenant ID. | 
| MsGraph.Alert.ThreatDisplayName | Unknown | Relevant only for Alerts v2. Alert threat display name. | 
| MsGraph.Alert.ThreatFamilyName | Unknown | Relevant only for Alerts v2. Alert threat family name. | 

#### Human Readable Output

>## Using Legacy Alerts:

>### Microsoft Security Graph Alerts

>## Microsoft Security Graph Alert Details - <alert_id>

>### Basic Properties

>|AzureTenantID|Category|CreatedDate|Description|EventDate|LastModifiedDate|Severity|Status|Title|
>|---|---|---|---|---|---|---|---|---|
>| <azure_tenant_id> | None | 2022-10-03T03:39:21.7562976Z | Created for test | 2022-09-26T05:01:02.839216Z | 2022-09-26T05:01:02.839216Z | medium | newAlert | test alert |

>### Customer Provided Comments for Alert

>- comment
>- comment

>### File Security States for Alert

>|FileHash|Name|Path|
>|---|---|---|
>| <file_hash> | crond | /usr/sbin |

>### Host Security States for Alert

>|Fqdn|OS|PrivateIPAddress|PublicIPAddress|RiskScore|
>|---|---|---|---|---|
>| `<fqdn>` | CentOS | <private_ip_address> | <public_ip_address> | medium |

>### User Security States for Alert

>|AccountName|EmailRole|
>|---|---|
>| root | unknown |

>### Vendor Information for Alert

>|Provider|SubProvider|Vendor|
>|---|---|---|
>| Microsoft Defender ATP | MicrosoftDefenderATP | Microsoft |

>## Using Alerts v2:

>### Microsoft Security Graph Alerts

>## Microsoft Security Graph Alert Details - <alert_id>

>|ID|IncidentId|Status|Severity|DetectionSource|ServiceSource|Title|Category|CreatedDate|LastUpdateDateTime|
>|---|---|---|---|---|---|---|---|---|---|
>| <alert_id> | <incident_id> | new | medium | customTi | microsoftDefenderForEndpoint | test alert | None | 2022-10-03T03:39:21.7562976Z | 2023-04-17T11:01:31.7566667Z |

### msg-update-alert

***
Update an editable alert property within any integrated solution to keep alert status and assignments in sync across solutions using its reference ID.

#### Base Command

`msg-update-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The Alert ID. Provider-generated GUID/unique identifier. | Required | 
| assigned_to | Name of the analyst the alert is assigned to for triage, investigation, or remediation. | Optional | 
| closed_date_time | Relevant only for Legacy Alerts. Time the alert was closed in the string format MM/DD/YYYY. | Optional | 
| comments | Relevant only for Legacy Alerts. Analyst comments on the alert (for customer alert management). | Optional | 
| feedback | Relevant only for Legacy Alerts. Analyst feedback on the alert. Possible values are: unknown, truePositive, falsePositive, benignPositive. | Optional | 
| status | Alert lifecycle status (stage). Possible values are: unknown, newAlert, inProgress, resolved, new. | Optional | 
| tags | Relevant only for Legacy Alerts. User-definable labels that can be applied to an alert and can serve as filter conditions, for example "HVA", "SAW). | Optional | 
| vendor_information | Relevant only for Legacy Alerts. Details about the security service vendor, for example Microsoft. | Optional | 
| provider_information | Relevant only for Legacy Alerts. Details about the security service vendor, for example Windows Defender ATP. | Optional | 
| classification | Relevant only for Alerts v2. Use this field to update the alert's classification. Possible values are: unknown, truePositive, falsePositive, benignPositive. | Optional | 
| determination | Relevant only for Alerts v2. Use this field to update the alert's determination. Possible values are: unknown, apt, malware, phishing, other, securityPersonnel, securityTesting, multiStagedAttack, maliciousUserActivity, lineOfBusinessApplication, unwantedSoftware. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Alert.ID | string | Alert ID. | 
| MsGraph.Alert.Status | string | Alert status, will appear only if changed. | 

#### Human Readable Output

>Alert <alert_id> has been successfully updated.

### msg-create-alert-comment

***
Relevant only for Alerts v2, create a comment for an existing alert.

#### Base Command

`msg-create-alert-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The Alert ID - Provider-generated GUID/unique identifier. | Required | 
| comment | The comment to add to each alert. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.AlertComment.ID | String | The alert ID that the comment was added to. | 
| MsGraph.AlertComment.Comments.Comment | String | The comment itself | 
| MsGraph.AlertComment.Comments.CreatedByDisplayName | String | The comment's creator display name | 
| MsGraph.AlertComment.Comments.CreatedDate | Date | The comment's creation time | 

#### Human Readable Output

>### Microsoft Security Graph Create Alert Comment - <alert_id>

>|comment|createdByDisplayName|createdDate|
>|---|---|---|
>| comment | Cortex XSOAR MS Graph Dev | 2023-04-17T10:57:18.5231438Z |
>| comment | Cortex XSOAR MS Graph Dev | 2023-04-17T11:01:31.7427859Z |
>| comment | Cortex XSOAR MS Graph Dev | 2023-04-17T13:30:22.3995128Z |


### ms-graph-security-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`ms-graph-security-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### msg-list-ediscovery-cases

***
Lists edicovery cases.

#### Base Command

`msg-list-ediscovery-cases`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. If provided, only this id will be returned. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoveryCase.CaseId | String | The ID of the eDiscovery case. | 
| MsGraph.eDiscoveryCase.CaseStatus | String | The case status. Possible values are: unknown, active, pendingDelete, closing, closed, and closedWithError. | 
| MsGraph.eDiscoveryCase.CreatedDateTime | Date | The date and time when the entity was created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z | 
| MsGraph.eDiscoveryCase.Description | String | The case description. | 
| MsGraph.eDiscoveryCase.DisplayName | String | The case name. | 
| MsGraph.eDiscoveryCase.ExternalId | String | The external case number for customer reference. | 
| MsGraph.eDiscoveryCase.LastModifiedDateTime | Date | The latest date and time when the case was modified. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z | 
| MsGraph.eDiscoveryCase.ClosedBy.User.DisplayName | String | The user who closed the case. | 
| MsGraph.eDiscoveryCase.LastModifiedBy.User.DisplayName | String | The user who last modified the case. | 
| MsGraph.eDiscoveryCase.ClosedDateTime | Date | The date and time when the case was closed. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z | 

#### Command example

```!msg-list-ediscovery-cases limit=5```

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoveryCase": [
            {
                "CaseId": "06386565-47d4-410b-96f9-007978319c02",
                "CaseStatus": "active",
                "ClosedBy": {
                    "User": {
                        "DisplayName": ""
                    }
                },
                "CreatedDateTime": "2023-06-18T10:55:12.63Z",
                "Description": "",
                "DisplayName": "a",
                "ExternalId": "123",
                "LastModifiedBy": {
                    "User": {
                        "DisplayName": "Content Test"
                    }
                },
                "LastModifiedDateTime": "2023-06-20T12:25:05.797Z"
            },
            {
                "CaseId": "44bbe68b-0da1-42b4-9ad0-00e8b52f64e2",
                "CaseStatus": "active",
                "ClosedBy": {
                    "User": {
                        "DisplayName": ""
                    }
                },
                "CreatedDateTime": "2023-06-18T11:59:33.44Z",
                "Description": "",
                "DisplayName": "asassdda",
                "ExternalId": "",
                "LastModifiedBy": {
                    "User": {
                        "DisplayName": "Content Test"
                    }
                },
                "LastModifiedDateTime": "2023-06-18T11:59:33.44Z"
            },
            {
                "CaseId": "f108b7fa-d177-438e-9679-01cd79e3df3f",
                "CaseStatus": "active",
                "ClosedBy": {
                    "User": {
                        "DisplayName": ""
                    }
                },
                "CreatedDateTime": "2023-06-20T07:08:01.95Z",
                "Description": "wrking",
                "DisplayName": "justw orkok?",
                "ExternalId": "",
                "LastModifiedBy": {
                    "User": {
                        "DisplayName": "Content Test"
                    }
                },
                "LastModifiedDateTime": "2023-06-20T07:08:01.95Z"
            },
            {
                "CaseId": "f346c6f5-1d66-4fab-a46b-0abc99c2cef0",
                "CaseStatus": "active",
                "ClosedBy": {
                    "User": {
                        "DisplayName": ""
                    }
                },
                "CreatedDateTime": "2023-06-18T11:54:59.873Z",
                "Description": "",
                "DisplayName": "asasdda",
                "ExternalId": "",
                "LastModifiedBy": {
                    "User": {
                        "DisplayName": "Content Test"
                    }
                },
                "LastModifiedDateTime": "2023-06-18T11:54:59.873Z"
            },
            {
                "CaseId": "1a346a94-5220-46ae-a821-0bbbadf4009d",
                "CaseStatus": "active",
                "ClosedBy": {
                    "User": {
                        "DisplayName": ""
                    }
                },
                "CreatedDateTime": "2023-06-12T07:05:27.557Z",
                "Description": "Test Case 104 description",
                "DisplayName": "Test Case 104",
                "ExternalId": "",
                "LastModifiedBy": {
                    "User": {
                        "DisplayName": "Content Test"
                    }
                },
                "LastModifiedDateTime": "2023-06-12T07:05:27.557Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Description|External Id|Case Status|Case Id|Created Date Time|Last Modified Date Time|Last Modified By Name|
>|---|---|---|---|---|---|---|---|
>| a |  | 123 | active | 06386565-47d4-410b-96f9-007978319c02 | 2023-06-18T10:55:12.63Z | 2023-06-20T12:25:05.797Z | Content Test |
>| asassdda |  |  | active | 44bbe68b-0da1-42b4-9ad0-00e8b52f64e2 | 2023-06-18T11:59:33.44Z | 2023-06-18T11:59:33.44Z | Content Test |
>| justw orkok? | wrking |  | active | f108b7fa-d177-438e-9679-01cd79e3df3f | 2023-06-20T07:08:01.95Z | 2023-06-20T07:08:01.95Z | Content Test |
>| asasdda |  |  | active | f346c6f5-1d66-4fab-a46b-0abc99c2cef0 | 2023-06-18T11:54:59.873Z | 2023-06-18T11:54:59.873Z | Content Test |
>| Test Case 104 | Test Case 104 description |  | active | 1a346a94-5220-46ae-a821-0bbbadf4009d | 2023-06-12T07:05:27.557Z | 2023-06-12T07:05:27.557Z | Content Test |

### msg-create-ediscovery-case

***
Create a new eDiscovery case. This command only creates an eDiscovery (Premium) case using the new case format. To learn more about the new case format in eDiscovery, see <https://learn.microsoft.com/en-us/microsoft-365/compliance/advanced-ediscovery-new-case-format>.

#### Base Command

`msg-create-ediscovery-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | The name of the eDiscovery case. | Required | 
| description | The case description. | Optional | 
| external_id | The external case number for customer reference. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoveryCase.CaseId | String | The ID of the eDiscovery case. | 
| MsGraph.eDiscoveryCase.CaseStatus | String | The case status. Possible values are unknown, active, pendingDelete, closing, closed, and closedWithError. | 
| MsGraph.eDiscoveryCase.CreatedDateTime | Date | The date and time when the entity was created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z | 
| MsGraph.eDiscoveryCase.Description | String | The case description. | 
| MsGraph.eDiscoveryCase.DisplayName | String | The case name. | 
| MsGraph.eDiscoveryCase.ExternalId | String | The external case number for customer reference. | 
| MsGraph.eDiscoveryCase.LastModifiedDateTime | Date | The latest date and time when the case was modified. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z | 

#### Command example

```!msg-create-ediscovery-case display_name=`my case name11234` external_id=123 description=`description of the case````

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoveryCase": {
            "CaseId": "6dfd17fe-43c5-411f-a194-abdc9492bfa0",
            "CaseStatus": "active",
            "CreatedDateTime": "2023-07-06T07:42:34.897Z",
            "Description": "description of the case",
            "DisplayName": "my case name11234",
            "ExternalId": "123",
            "LastModifiedDateTime": "2023-07-06T07:42:34.897Z"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Description|External Id|Case Status|Case Id|Created Date Time|Last Modified Date Time|
>|---|---|---|---|---|---|---|
>| my case name11234 | description of the case | 123 | active | 6dfd17fe-43c5-411f-a194-abdc9492bfa0 | 2023-07-06T07:42:34.897Z | 2023-07-06T07:42:34.897Z |

### msg-update-ediscovery-case

***
Update an eDiscovery case.

#### Base Command

`msg-update-ediscovery-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| display_name | The name of the eDiscovery case. | Required | 
| description | The case description. | Optional | 
| external_id | The external case number for customer reference. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-update-ediscovery-case case_id=6dfd17fe-43c5-411f-a194-abdc9492bfa0 display_name=`new display name` external_id=123 description=`new description of the case````

#### Human Readable Output

>Case with id 6dfd17fe-43c5-411f-a194-abdc9492bfa0 was updated successfully.

### msg-close-ediscovery-case

***
Close an eDiscovery case. 
When the legal case or investigation supported by a eDiscovery (Standard) case is completed, you can close the case. Here's what happens when you close a case:
      If the case contains any eDiscovery holds, they'll be turned off. After the hold is turned off, a 30-day grace period (called a delay hold) is applied to content locations that were on hold. This helps prevent content from being immediately deleted and provides admins the opportunity to search for and restore content before it may be permanently deleted after the delay hold period expires. For more information, see Removing content locations from an eDiscovery hold.
      Closing a case only turns off the holds that are associated with that case. If other holds are placed on a content location (such as a Litigation Hold, a retention policy, or a hold from a different eDiscovery (Standard) case) those holds will still be maintained.
      The case is still listed on the eDiscovery (Standard) page in the Microsoft Purview compliance portal. The details, holds, searches, and members of a closed case are retained.
      You can edit a case after it's closed. For example, you can add or remove members, create searches, and export search results. The primary difference between active and closed cases is that eDiscovery holds are turned off when a case is closed.

#### Base Command

`msg-close-ediscovery-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-close-ediscovery-case case_id=6dfd17fe-43c5-411f-a194-abdc9492bfa0```

#### Human Readable Output

>Case with id 6dfd17fe-43c5-411f-a194-abdc9492bfa0 was closed successfully.

### msg-reopen-ediscovery-case

***
Reopen an eDiscovery case. When you reopen an eDiscovery (Premium) case, any holds that were in place when the case was closed won't be automatically reinstated. After the case is reopened, you'll have to go to the Holds tab and turn on the previous holds. To turn on a hold, select it to display the flyout page, and then set the Status toggle to On.

#### Base Command

`msg-reopen-ediscovery-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-reopen-ediscovery-case case_id=6dfd17fe-43c5-411f-a194-abdc9492bfa0```

#### Human Readable Output

>Case with id 6dfd17fe-43c5-411f-a194-abdc9492bfa0 was reopened successfully.

### msg-delete-ediscovery-case

***
Delete an eDiscovery case. Before you can delete a case, you must first delete all holds listed on the holds page of the case. That includes deleting holds with a status of Off. Default hold policies can only be deleted when the hold is turned off. You must close an active case to turn off any default hold policies in the case. Once the holds are turned off for default hold policies, they can be deleted.

#### Base Command

`msg-delete-ediscovery-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-delete-ediscovery-case case_id=6dfd17fe-43c5-411f-a194-abdc9492bfa0```

#### Human Readable Output

>Case was deleted successfully.

### msg-create-ediscovery-custodian

***
Create a new ediscoveryCustodian object. After the custodian object is created, you will need to create the custodian's userSource to reference their mailbox and OneDrive for Business site.

#### Base Command

`msg-create-ediscovery-custodian`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| email | Custodian's primary SMTP address. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoveryCustodian.CreatedDateTime | Date | Date and time when the custodian was added to the case. | 
| MsGraph.eDiscoveryCustodian.CustodianId | String | The ID for the custodian in the specified case. Read-only. | 
| MsGraph.eDiscoveryCustodian.CustodianStatus | String | Status of the custodian. Possible values are: active, released. | 
| MsGraph.eDiscoveryCustodian.DisplayName | String | Display name of the custodian. | 
| MsGraph.eDiscoveryCustodian.Email | String | Email address of the custodian. | 
| MsGraph.eDiscoveryCustodian.HoldStatus | String | The hold status of the custodian.The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.eDiscoveryCustodian.LastModifiedDateTime | Date | Date and time the custodian object was last modified. | 

#### Command example

```!msg-create-ediscovery-custodian case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 email=testbox2@yoursite.onmicrosoft.com```

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoveryCustodian": {
            "CreatedDateTime": "2023-07-06T07:53:36.9441479Z",
            "CustodianId": "0af7ca2b84bc4cff930d5d301cc4caf3",
            "CustodianStatus": "active",
            "DisplayName": "testbox2",
            "Email": "yourmail@yoursite.onmicrosoft.com",
            "HoldStatus": "notApplied",
            "LastModifiedDateTime": "2023-07-06T07:53:36.9441479Z"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name| Email                             |Custodian Status|Custodian Id|Created Date Time|Last Modified Date Time|Hold Status|
>|-----------------------------------|---|---|---|---|---|---|
>| testbox2 | yourmail@yoursite.onmicrosoft.com | active | 0af7ca2b84bc4cff930d5d301cc4caf3 | 2023-07-06T07:53:36.9441479Z | 2023-07-06T07:53:36.9441479Z | notApplied |

### msg-list-ediscovery-custodians

***
List custodians on a given eDiscovery case.

#### Base Command

`msg-list-ediscovery-custodians`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the custodian on the given eDiscovery case. If provided, only this ID will be returned. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoveryCustodian.CreatedDateTime | Date | Date and time when the custodian was added to the case. | 
| MsGraph.eDiscoveryCustodian.CustodianId | String | The ID for the custodian in the specified case. Read-only. | 
| MsGraph.eDiscoveryCustodian.CustodianStatus | String | Status of the custodian. Possible values are: active, released. | 
| MsGraph.eDiscoveryCustodian.DisplayName | String | Display name of the custodian. | 
| MsGraph.eDiscoveryCustodian.Email | String | Email address of the custodian. | 
| MsGraph.eDiscoveryCustodian.HoldStatus | String | The hold status of the custodian. The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.eDiscoveryCustodian.LastModifiedDateTime | Date | Date and time the custodian object was last modified. | 
| MsGraph.eDiscoveryCustodian.ReleasedDateTime | Date | Date and time the custodian was released from the case. | 

#### Command example

```!msg-list-ediscovery-custodians all_results=true case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoveryCustodian": {
            "CreatedDateTime": "2023-07-06T07:53:36.9441479Z",
            "CustodianId": "0af7ca2b84bc4cff930d5d301cc4caf3",
            "CustodianStatus": "active",
            "DisplayName": "testbox2",
            "Email": "mail@yoursite.onmicrosoft.com",
            "HoldStatus": "notApplied",
            "LastModifiedDateTime": "2023-07-06T07:53:36.9441479Z"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name| Email                         |Custodian Status|Custodian Id|Created Date Time|Last Modified Date Time|Hold Status|
>|-------------------------------|---|---|---|---|---|---|
>| testbox2 | mail@yoursite.onmicrosoft.com | active | 0af7ca2b84bc4cff930d5d301cc4caf3 | 2023-07-06T07:53:36.9441479Z | 2023-07-06T07:53:36.9441479Z | notApplied |

### msg-activate-ediscovery-custodian

***
Activate a custodian that has been released from a case to make them part of the case again. For details, see <https://learn.microsoft.com/en-us/microsoft-365/compliance/ediscovery-manage-new-custodians?view=o365-worldwide#re-activate-custodian>.

#### Base Command

`msg-activate-ediscovery-custodian`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-activate-ediscovery-custodian custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Human Readable Output

>Custodian with id 0af7ca2b84bc4cff930d5d301cc4caf3 Case was reactivated on case with id 84abfff1-dd69-4559-8f4e-8225e0d505c5 successfully.

### msg-release-ediscovery-custodian

***
Release a custodian from a case. For details, see <https://learn.microsoft.com/en-us/microsoft-365/compliance/manage-new-custodians#release-a-custodian-from-a-case>.

#### Base Command

`msg-release-ediscovery-custodian`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-release-ediscovery-custodian custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Human Readable Output

>Custodian with id 0af7ca2b84bc4cff930d5d301cc4caf3 was released from case with id 84abfff1-dd69-4559-8f4e-8225e0d505c5 successfully.

### msg-create-ediscovery-custodian-site-source

***
Create a new siteSource object associated with an eDiscovery custodian. Use the msg-list-ediscovery-custodians command in order to get all available custodians.

#### Base Command

`msg-create-ediscovery-custodian-site-source`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 
| site | URL of the site; for example, <https://contoso.sharepoint.com/sites/HumanResources>. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.CustodianSiteSource.CreatedBy.Application.DisplayName | String | The name of the application who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.Application.ID | String | The ID of the application who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.DisplayName | String | The name of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.ID | String | The ID of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedDateTime | Date | The date and time the siteSource was created. | 
| MsGraph.CustodianSiteSource.DisplayName | String | The display name of the siteSource. This will be the name of the SharePoint site. | 
| MsGraph.CustodianSiteSource.HoldStatus | String | The hold status of the siteSource. The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.CustodianSiteSource.SiteSourceId | String | The ID of the siteSource. | 

#### Command example

```!msg-create-ediscovery-custodian-site-source custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5  site=https://yourdev.sharepoint.com/sites/site_test_1```

#### Context Example

```json
{
    "MsGraph": {
        "CustodianSiteSource": {
            "CreatedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "CreatedDateTime": "0001-01-01T00:00:00Z",
            "DisplayName": "site_test_1",
            "HoldStatus": "notApplied",
            "SiteSourceId": "862f0a64-e7db-46e0-a97f-9156b4f693ee"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Site Source Id|Hold Status|Created Date Time|Created By Name|Created By UPN|Created By App Name|
>|---|---|---|---|---|---|---|
>| site_test_1 | 862f0a64-e7db-46e0-a97f-9156b4f693ee | notApplied | 0001-01-01T00:00:00Z | Content Test | ContentTest@yoursite.onmicrosoft.com | Cortex XSOAR - MS Graph Security Dev |

### msg-create-ediscovery-custodian-user-source

***
Create a new userSource object associated with an eDiscovery custodian. Use the msg-list-ediscovery-custodians command in order to get all available custodians.

#### Base Command

`msg-create-ediscovery-custodian-user-source`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 
| email | SMTP address of the user. | Required | 
| included_sources | Specifies which sources are included in this group. Possible values are: mailbox, site, mailbox, site. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.CustodianUserSource.CreatedBy.Application.DisplayName | String | The name of the application who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.Application.ID | String | The ID of the application who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.DisplayName | String | The name of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.ID | String | The ID of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedDateTime | Date | The date and time the userSource was created. | 
| MsGraph.CustodianUserSource.DisplayName | String | The display name associated with the mailbox and site. | 
| MsGraph.CustodianUserSource.Email | String | Email address of the user's mailbox. | 
| MsGraph.CustodianUserSource.HoldStatus | String | The hold status of the userSource. The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.CustodianUserSource.IncludedSources | String | Specifies which sources are included in this group. Possible values are: mailbox, site. | 
| MsGraph.CustodianUserSource.UserSourceId | String | The ID of the userSource. This is not The ID of the actual group. | 

#### Command example

```!msg-create-ediscovery-custodian-user-source custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5  email=testbox2@yoursite.onmicrosoft.com included_sources="mailbox, site"```

#### Context Example

```json
{
    "MsGraph": {
        "CustodianUserSource": {
            "CreatedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "CreatedDateTime": "0001-01-01T00:00:00Z",
            "DisplayName": "testbox2",
            "Email": "testbox2@yoursite.onmicrosoft.com",
            "HoldStatus": "notApplied",
            "IncludedSources": "mailbox,site",
            "UserSourceId": "0af7ca2b-84bc-4cff-930d-5d301cc4caf3"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Email|User Source Id|Hold Status|Created Date Time|Created By Name|Created By UPN|Created By App Name|Included Sources|
>|---|---|---|---|---|---|---|---|---|
>| testbox2 | testbox2@yoursite.onmicrosoft.com | 0af7ca2b-84bc-4cff-930d-5d301cc4caf3 | notApplied | 0001-01-01T00:00:00Z | Content Test | ContentTest@yoursite.onmicrosoft.com | Cortex XSOAR - MS Graph Security Dev | mailbox,site |

### msg-list-ediscovery-custodian-user-sources

***
Get a list of the userSource objects associated with an eDiscoveryCustodian. Use the msg-list-ediscovery-custodians command in order to get all available custodians.

#### Base Command

`msg-list-ediscovery-custodian-user-sources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 
| user_source_id | The ID of the userSource. If provided, only this id will be returned. | Optional | 
| limit | Number of total results to return. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.CustodianUserSource.CreatedBy.Application.DisplayName | String | The name of the application who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.Application.ID | String | The ID of the application who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.DisplayName | String | The name of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.ID | String | The ID of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the userSource. | 
| MsGraph.CustodianUserSource.CreatedDateTime | Date | The date and time the userSource was created. | 
| MsGraph.CustodianUserSource.DisplayName | String | The display name associated with the mailbox and site. | 
| MsGraph.CustodianUserSource.Email | String | Email address of the user's mailbox. | 
| MsGraph.CustodianUserSource.HoldStatus | String | The hold status of the userSource. The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.CustodianUserSource.IncludedSources | String | Specifies which sources are included in this group. Possible values are: mailbox, site. | 
| MsGraph.CustodianUserSource.SiteWebUrl | String | The URL of the user's OneDrive for Business site. Read-only. | 
| MsGraph.CustodianUserSource.UserSourceId | String | The ID of the userSource. This is not The ID of the actual group. | 

#### Command example

```!msg-list-ediscovery-custodian-user-sources custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Context Example

```json
{
    "MsGraph": {
        "CustodianUserSource": {
            "CreatedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "CreatedDateTime": "2023-07-06T08:04:21.1548801Z",
            "DisplayName": "testbox2",
            "Email": "testbox2@yoursite.onmicrosoft.com",
            "HoldStatus": "notApplied",
            "IncludedSources": "mailbox,site",
            "SiteWebUrl": "https://yourdev-my.sharepoint.com/personal/testbox2_yourdev_onmicrosoft_com",
            "UserSourceId": "0af7ca2b-84bc-4cff-930d-5d301cc4caf3"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Email|User Source Id|Hold Status|Created Date Time|Created By Name|Created By UPN|Created By App Name|Site Web Url|Included Sources|
>|---|---|---|---|---|---|---|---|---|---|
>| testbox2 | testbox2@yoursite.onmicrosoft.com | 0af7ca2b-84bc-4cff-930d-5d301cc4caf3 | notApplied | 2023-07-06T08:04:21.1548801Z | Content Test | ContentTest@yoursite.onmicrosoft.com | Cortex XSOAR - MS Graph Security Dev | https://yourdev-my.sharepoint.com/personal/testbox2_yourdev_onmicrosoft_com | mailbox,site |

### msg-list-ediscovery-custodian-site-sources

***
Get a list of the siteSource objects associated with an eDiscoveryCustodian. Use the msg-list-ediscovery-custodians command in order to get all available custodians.

#### Base Command

`msg-list-ediscovery-custodian-site-sources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | The ID of the eDiscovery case. on the given eDiscovery case. | Required | 
| site_source_id | The ID of the siteSource. If provided, only this id will be returned. | Optional | 
| limit | Number of total results to return. Default is 50. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.CustodianSiteSource.CreatedBy.Application.DisplayName | String | The name of the application who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.Application.ID | String | The ID of the application who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.DisplayName | String | The name of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.ID | String | The ID of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the siteSource. | 
| MsGraph.CustodianSiteSource.CreatedDateTime | Date | The date and time the siteSource was created. | 
| MsGraph.CustodianSiteSource.DisplayName | String | The display name of the siteSource. This will be the name of the SharePoint site. | 
| MsGraph.CustodianSiteSource.HoldStatus | String | The hold status of the siteSource. The possible values are: notApplied, applied, applying, removing, partial. | 
| MsGraph.CustodianSiteSource.SiteSourceId | String | The ID of the siteSource. | 
| MsGraph.CustodianSiteSource.Site.ID | String | The unique identifier of the item. Read-only. | 
| MsGraph.CustodianSiteSource.Site.WebUrl | String | URL that displays the item in the browser. Read-only. | 
| MsGraph.CustodianSiteSource.Site.CreatedDate | Date | The date and time the siteSource was created. | 

#### Command example

```!msg-list-ediscovery-custodian-site-sources custodian_id=0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5  site_source_id=862f0a64-e7db-46e0-a97f-9156b4f693ee```

#### Context Example

```json
{
    "MsGraph": {
        "CustodianSiteSource": {
            "CreatedBy": {
                "User": {
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b"
                }
            },
            "CreatedDateTime": "2023-07-06T08:02:28.5670187Z",
            "DisplayName": "site_test_1",
            "HoldStatus": "removing",
            "Site": {
                "CreatedDate": "2023-07-06T08:02:28.5670187Z",
                "ID": "862f0a64-e7db-46e0-a97f-9156b4f693ee",
                "WebUrl": "https://yourdev.sharepoint.com/sites/site_test_1"
            },
            "SiteSourceId": "862f0a64-e7db-46e0-a97f-9156b4f693ee"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Site Source Id|Hold Status|Created Date Time|
>|---|---|---|---|
>| site_test_1 | 862f0a64-e7db-46e0-a97f-9156b4f693ee | removing | 2023-07-06T08:02:28.5670187Z |


### msg-apply-hold-ediscovery-custodian

***
Start the process of applying hold on eDiscovery custodians.
Available return statuses: 
notApplied - The custodian is not on hold (all sources in it are not on hold).
applied - The custodian is on hold (all sources are on hold).
applying - The custodian is in applying hold state (applyHold operation triggered).
removing - The custodian is in removing the hold state(removeHold operation triggered).
partial - The custodian is in mixed state where some sources are on hold and some not on hold or error state.

#### Base Command

`msg-apply-hold-ediscovery-custodian`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | A comma-seperated list of custodians ids to apply a hold to. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-apply-hold-ediscovery-custodian custodian_id=09f05c43ffc54ff88cf5c5e89699375d,0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Human Readable Output

>Apply hold status is running.

### msg-remove-hold-ediscovery-custodian

***
Start the process of removing hold from eDiscovery custodians.

#### Base Command

`msg-remove-hold-ediscovery-custodian`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| custodian_id | A comma-seperated list of custodians ids to remove a hold from. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-remove-hold-ediscovery-custodian custodian_id=09f05c43ffc54ff88cf5c5e89699375d,0af7ca2b84bc4cff930d5d301cc4caf3 case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Human Readable Output

>Remove hold status is running.

### msg-create-ediscovery-non-custodial-data-source

***
Create a new eDiscoveryNoncustodialDataSource object.

#### Base Command

`msg-create-ediscovery-non-custodial-data-source`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| site | URL of the site, for example, <https://contoso.sharepoint.com/sites/HumanResources>. | Optional | 
| email | Email address of the user's mailbox. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.NoncustodialDataSource.CreatedDateTime | Date | Created date and time of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.DataSourceId | String | Unique identifier of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.DataSourceStatus | String | Latest status of the nonCustodialDataSource. Possible values are: Active, Released. | 
| MsGraph.NoncustodialDataSource.DisplayName | String | Display name of the noncustodialDataSource. | 
| MsGraph.NoncustodialDataSource.HoldStatus | String | The hold status of the nonCustodialDataSource.The possible values are: notApplied, applied, applying, removing, partial | 
| MsGraph.NoncustodialDataSource.LastModifiedDateTime | Date | Last modified date and time of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.ReleasedDateTime | Date | Date and time that the nonCustodialDataSource was released from the case. | 

#### Command example

```!msg-create-ediscovery-non-custodial-data-source case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 site=https://yourdev.sharepoint.com/sites/site_test_1```

#### Context Example

```json
{
    "MsGraph": {
        "NoncustodialDataSource": {
            "CreatedDateTime": "2023-07-06T08:22:32.3121523Z",
            "DataSourceId": "38394332433939353236344630434633",
            "DataSourceStatus": "active",
            "DisplayName": "site_test_1",
            "HoldStatus": "notApplied",
            "LastModifiedDateTime": "2023-07-06T08:22:32.3121523Z",
            "ReleasedDateTime": "0001-01-01T00:00:00Z"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Created Date Time|Data Source Id|Data Source Status|Display Name|Hold Status|Last Modified Date Time|Released Date Time|
>|---|---|---|---|---|---|---|
>| 2023-07-06T08:22:32.3121523Z | 38394332433939353236344630434633 | active | site_test_1 | notApplied | 2023-07-06T08:22:32.3121523Z | 0001-01-01T00:00:00Z |

### msg-list-ediscovery-non-custodial-data-sources

***
Get a list of the non-custodial data sources and their properties.

#### Base Command

`msg-list-ediscovery-non-custodial-data-sources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| data_source_id | The ID of the dataSource. If provided, only this id will be returned. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.NoncustodialDataSource.CreatedDateTime | Date | Created date and time of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.DataSourceId | String | Unique identifier of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.DataSourceStatus | String | Latest status of the nonCustodialDataSource. Possible values are: Active, Released. | 
| MsGraph.NoncustodialDataSource.DisplayName | String | Display name of the noncustodialDataSource. | 
| MsGraph.NoncustodialDataSource.HoldStatus | String | The hold status of the nonCustodialDataSource.The possible values are: notApplied, applied, applying, removing, partial | 
| MsGraph.NoncustodialDataSource.LastModifiedDateTime | Date | Last modified date and time of the nonCustodialDataSource. | 
| MsGraph.NoncustodialDataSource.ReleasedDateTime | Date | Date and time that the nonCustodialDataSource was released from the case. | 

#### Command example

```!msg-list-ediscovery-non-custodial-data-sources case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Context Example

```json
{
    "MsGraph": {
        "NoncustodialDataSource": {
            "CreatedDateTime": "2023-07-06T08:22:32.3121523Z",
            "DataSourceId": "38394332433939353236344630434633",
            "DisplayName": "site_test_1",
            "HoldStatus": "notApplied",
            "LastModifiedDateTime": "2023-07-06T08:22:32.3121523Z",
            "ReleasedDateTime": "0001-01-01T00:00:00Z",
            "Status": "active"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Data Source Id|Hold Status|Created Date Time|Last Modified Date Time|Released Date Time|Status|
>|---|---|---|---|---|---|---|
>| site_test_1 | 38394332433939353236344630434633 | notApplied | 2023-07-06T08:22:32.3121523Z | 2023-07-06T08:22:32.3121523Z | 0001-01-01T00:00:00Z | active |

### msg-create-ediscovery-search

***
Create a new eDiscoverySearch object.

#### Base Command

`msg-create-ediscovery-search`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                   | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| case_id | The ID of the eDiscovery case.                                                                                                                                                                                                                                                                                                                    | Required | 
| display_name | The display name of the search.                                                                                                                                                                                                                                                                                                                   | Required | 
| description | The description of the search.                                                                                                                                                                                                                                                                                                                    | Optional | 
| content_query | The query string used for the search. The query string format is KQL (Keyword Query Language). For details, see <https://learn.microsoft.com/en-us/microsoft-365/compliance/keyword-queries-and-search-conditions.>. You can refine searches by using fields paired with values; for example, subject:"Quarterly Financials" AND Date&gt;=06/01/2016 AND Date&lt;=07/01/2016. | Optional | 
| data_source_scopes | When specified, the collection will span across a service for an entire workload. Possible values are: none, allTenantMailboxes, allTenantSites, allCaseCustodians, allCaseNoncustodialDataSources.                                                                                                                                               | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoverySearch.ContentQuery | String | The query string in KQL \(Keyword Query Language\) query. For details, see  see <https://learn.microsoft.com/en-us/microsoft-365/compliance/keyword-queries-and-search-conditions.>. You can refine searches by using fields paired with values; for example, subject:"Quarterly Financials" AND Date&gt;=06/01/2016 AND Date&lt;=07/01/2016. | 
| MsGraph.eDiscoverySearch.CreatedBy.Application.DisplayName | String | Name of the application who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.Application.ID | String | ID of the application who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.DisplayName | String | Name of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.ID | String | ID of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedDateTime | Date | The date and time the eDiscovery search was created. | 
| MsGraph.eDiscoverySearch.DataSourceScopes | String | When specified, the collection will span across a service for an entire workload. Possible values are: none, allTenantMailboxes, allTenantSites, allCaseCustodians, allCaseNoncustodialDataSources. | 
| MsGraph.eDiscoverySearch.Description | String | The description of the eDiscovery search. | 
| MsGraph.eDiscoverySearch.DisplayName | String | The display name of the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedDateTime | Date | The last date and time the eDiscovery search was modified. | 
| MsGraph.eDiscoverySearch.SearchId | String | The ID for the eDiscovery search. | 

#### Command example

```!msg-create-ediscovery-search case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 display_name=`my search` data_source_scopes=allCaseNoncustodialDataSources```

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoverySearch": {
            "ContentQuery": "",
            "CreatedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "CreatedDateTime": "2023-07-06T08:25:36.9874937Z",
            "DataSourceScopes": "allCaseNoncustodialDataSources",
            "Description": "",
            "DisplayName": "my search",
            "LastModifiedDateTime": "2023-07-06T08:25:36.9874937Z",
            "SearchId": "e7282eff-ba81-43cb-9027-522a343f6692"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Data Source Scopes|Search Id|Created By Name|Created By App Name|Created By UPN|Created Date Time|Last Modified Date Time|
>|---|---|---|---|---|---|---|---|
>| my search | allCaseNoncustodialDataSources | e7282eff-ba81-43cb-9027-522a343f6692 | Content Test | Cortex XSOAR - MS Graph Security Dev | ContentTest@yoursite.onmicrosoft.com | 2023-07-06T08:25:36.9874937Z | 2023-07-06T08:25:36.9874937Z |

### msg-update-ediscovery-search

***
Update an eDiscoverySearch object.

#### Base Command

`msg-update-ediscovery-search`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                                                   | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| case_id | The ID of the eDiscovery case.                                                                                                                                                                                                                                                                                                                    | Required | 
| search_id | The ID of the eDiscovery search.                                                                                                                                                                                                                                                                                                                  | Required | 
| display_name | The display name of the search.                                                                                                                                                                                                                                                                                                                   | Required | 
| description | The description of the search.                                                                                                                                                                                                                                                                                                                    | Optional | 
| content_query | The query string used for the search. The query string format is KQL (Keyword Query Language). For details, see Keyword queries and search conditions for Content Search and eDiscovery. You can refine searches by using fields paired with values, for example, subject:"Quarterly Financials" AND Date&gt;=06/01/2016 AND Date&lt;=07/01/2016. | Optional | 
| data_source_scopes | When specified, the collection will span across a service for an entire workload. Possible values are: none, allTenantMailboxes, allTenantSites, allCaseCustodians, allCaseNoncustodialDataSources.                                                                                                                                               | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-update-ediscovery-search case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 display_name=newname search_id=e7282eff-ba81-43cb-9027-522a343f6692```

#### Human Readable Output

>eDiscovery search e7282eff-ba81-43cb-9027-522a343f6692 was updated successfully.

### msg-list-ediscovery-searchs

***
Get the list of eDiscoverySearch resources from an eDiscovery case.

#### Base Command

`msg-list-ediscovery-searchs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| search_id | The ID of the eDiscovery search. If provided, only this id will be returned. | Optional | 
| limit | The maximum number of results to return. Default is 50. | Optional | 
| all_results | Show all results if true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.eDiscoverySearch.ContentQuery | String | The query string in KQL \(Keyword Query Language\) query. For details, see Keyword queries and search conditions for Content Search and eDiscovery. You can refine searches by using fields paired with values; for example, subject:"Quarterly Financials" AND Date&gt;=06/01/2016 AND Date&lt;=07/01/2016. | 
| MsGraph.eDiscoverySearch.CreatedBy.Application.DisplayName | String | Name of the application who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.Application.ID | String | ID of the application who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.DisplayName | String | Name of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.ID | String | ID of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedBy.User.UserPrincipalName | String | Internet-style login name of the user who created the eDiscovery search. | 
| MsGraph.eDiscoverySearch.CreatedDateTime | Date | The date and time the eDiscovery search was created. | 
| MsGraph.eDiscoverySearch.DataSourceScopes | String | When specified, the collection will span across a service for an entire workload. Possible values are: none, allTenantMailboxes, allTenantSites, allCaseCustodians, allCaseNoncustodialDataSources. | 
| MsGraph.eDiscoverySearch.Description | String | The description of the eDiscovery search. | 
| MsGraph.eDiscoverySearch.DisplayName | String | The display name of the eDiscovery search. | 
| MsGraph.eDiscoverySearch.SearchId | String | The ID for the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedDateTime | String | The last date and time the eDiscovery search was modified. | 
| MsGraph.eDiscoverySearch.LastModifiedBy.Application.DisplayName | String | Name of the application who last modified the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedBy.Application.ID | String | ID of the application who last modified the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedBy.User.DisplayName | String | Name of the user who last modified the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedBy.User.ID | String | ID of the user who last modified the eDiscovery search. | 
| MsGraph.eDiscoverySearch.LastModifiedBy.User.UserPrincipalName | String | Internet-style login name of the user who last modified the eDiscovery search. | 

#### Command example

```!msg-list-ediscovery-searchs case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5```

#### Context Example

```json
{
    "MsGraph": {
        "eDiscoverySearch": {
            "ContentQuery": "",
            "CreatedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "CreatedDateTime": "2023-07-06T08:25:36.9874937Z",
            "DataSourceScopes": "allCaseNoncustodialDataSources",
            "Description": "",
            "DisplayName": "newname",
            "LastModifiedBy": {
                "Application": {
                    "DisplayName": "Cortex XSOAR - MS Graph Security Dev",
                    "ID": "734f96d8-b19c-4ab1-9382-e04aa9a5debd"
                },
                "User": {
                    "DisplayName": "Content Test",
                    "ID": "38c41451-94b8-44cc-8c02-649208c43b6b",
                    "UserPrincipalName": "ContentTest@yoursite.onmicrosoft.com"
                }
            },
            "LastModifiedDateTime": "2023-07-06T08:27:51.5611704Z",
            "SearchId": "e7282eff-ba81-43cb-9027-522a343f6692"
        }
    }
}
```

#### Human Readable Output

>### Results:

>|Display Name|Data Source Scopes|Search Id|Created By Name|Created By App Name|Created By UPN|Created Date Time|Last Modified Date Time|
>|---|---|---|---|---|---|---|---|
>| newname | allCaseNoncustodialDataSources | e7282eff-ba81-43cb-9027-522a343f6692 | Content Test | Cortex XSOAR - MS Graph Security Dev | ContentTest@yoursite.onmicrosoft.com | 2023-07-06T08:25:36.9874937Z | 2023-07-06T08:27:51.5611704Z |

### msg-purge-ediscovery-data

***
Delete Microsoft Teams messages contained in an eDiscovery search.
Note: This request purges Teams data only. It does not purge other types of data such as mailbox items.

You can collect and purge the following categories of Teams content:

Teams 1:1 chats - Chat messages, posts, and attachments shared in a Teams conversation between two people. Teams 1:1 chats are also called conversations.
Teams group chats - Chat messages, posts, and attachments shared in a Teams conversation between three or more people. Also called 1:N chats or group conversations.
Teams channels - Chat messages, posts, replies, and attachments shared in a standard Teams channel.
Private channels - Message posts, replies, and attachments shared in a private Teams channel.
Shared channels - Message posts, replies, and attachments shared in a shared Teams channel.

#### Base Command

`msg-purge-ediscovery-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| search_id | The ID of the eDiscovery search. | Required | 
| purge_type | The ID of the eDiscovery search. Possible values are: permanentlyDelete. | Optional | 
| purge_areas | The ID of the eDiscovery search. Possible values are: teamsMessages. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-purge-ediscovery-data case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 search_id=e7282eff-ba81-43cb-9027-522a343f6692```

#### Human Readable Output

>eDiscovery purge status is running.

### msg-delete-ediscovery-search

***
Delete an eDiscoverySearch object.

#### Base Command

`msg-delete-ediscovery-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The ID of the eDiscovery case. | Required | 
| search_id | The ID of the eDiscovery search. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example

```!msg-delete-ediscovery-search case_id=84abfff1-dd69-4559-8f4e-8225e0d505c5 search_id=e7282eff-ba81-43cb-9027-522a343f6692```

#### Human Readable Output

>eDiscovery search e7282eff-ba81-43cb-9027-522a343f6692 was deleted successfully.

### msg-generate-login-url

***
Generate the login URL used for authorization code flow.

#### Base Command

`msg-generate-login-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

#### Human Readable Output

>### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
>```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.
