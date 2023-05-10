Unified gateway to security insights - all from a unified Microsoft Graph Security API.
This integration was integrated and tested with version 1.0 of Microsoft Graph.

## Authentication
For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication)

## Note
The `message-search-alerts` command does not filter alerts of the `Office 365` provider because of API limitations.\
For more info, see: https://github.com/microsoftgraph/security-api-solutions/issues/56.

### Required Permissions
1. SecurityEvents.Read.All - Application (required for the commands: `msg-search-alerts` and `msg-get-alert-details`
2. SecurityEvents.ReadWrite.All - Application (required for updating alerts with the command: `msg-update-alert`)
3. User.Read.All - Application (Only required if using the deprecated commands: `msg-get-user` and `msg-get-users`)

## Configure Microsoft Graph Security on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Graph Security.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Host URL | The host URL. | True |
    | Application ID or Client ID | The app registration ID. | True |
    | Token or Tenant ID | The tenant ID. | True |
    | Key or Client Secret | The app registration secret. | False |
    | Certificate Thumbprint | Used for certificate authentication, as it appears in the "Certificates & secrets" page of the app. | False |
    | Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
    | Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
    | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
    | Trust any certificate (not secure) | Whether to trust any certificate. If True, not secure. | False |
    | Use system proxy settings | Whether to use system proxy settings. | False |
    | Use a self-deployed Azure application | Whether to use a self-deployed application. | False |
    | Fetch incidents | Whether to fetch incidents. | False |
    | Incident type | The incident type to apply. | False |
    | First fetch time range | &lt;number&gt; &lt;time unit&gt;, for example 1 hour, 30 minutes. | False |
    | How many incidents to fetch each time | The number of incidents to fetch. | False |
    | Fetch incidents of the given providers only. | Multiple providers can be inserted separated by a comma, for example "\{first_provider\},\{second_provider\}". If empty, incidents of all providers will be fetched. | False |
    | Fetched incidents filter | Use this field to filter fetched incidents according to any of the alert properties. Overrides the providers list, if given. Filter should be in the format "{property} eq '{property-value}'". Multiple filters can be applied separated with " and ", for example "createdDateTime eq YYYY-MM-DD and severity eq 'high'". | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
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
| category | Category of the alert, for example credentialTheft, ransomware (Categories can be added or removed by vendors.). | Optional | 
| time_from | The start time (creation time of alert) for the search in the string format YYYY-MM-DD. | Optional | 
| time_to | The end time (creation time of alert) for the search in the string format YYYY-MM-DD. | Optional | 
| filter | Use this field to filter on any of the alert properties in the format "{property} eq '{property-value}'", for example "category eq 'ransomware'". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Alert.ID | string | Alert ID. | 
| MsGraph.Alert.Title | string | Alert title. | 
| MsGraph.Alert.Category | string | Alert category. | 
| MsGraph.Alert.Severity | string | Alert severity. | 
| MsGraph.Alert.CreatedDate | date | Alert creation date. | 
| MsGraph.Alert.EventDate | date | Alert event time. | 
| MsGraph.Alert.Status | string | Alert status. | 
| MsGraph.Alert.Vendor | string | Alert vendor/provider. | 
| MsGraph.Alert.MalwareStates | string | Alert malware states. | 
| MsGraph.Alert.Vendor | string | Alert vendor. | 
| MsGraph.Alert.Provider | string | Alert provider. | 

### msg-get-alert-details
***
Get details for a specific alert.


#### Base Command

`msg-get-alert-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The Alert ID. Provider-generated GUID/unique identifier. | Required | 
| fields_to_include | Fields to fetch for specified Alert apart from the basic properties, given as comma separated values, for example NetworkConnections,Processes. Optional values: All,NetworkConnections,Processes,RegistryKeys,UserStates,HostStates,FileStates,CloudAppStates,MalwareStates,CustomerComment,Triggers,VendorInformation,VulnerabilityStates. Default is All. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Alert.ID | string | Alert ID. | 
| MsGraph.Alert.Title | string | Alert title. | 
| MsGraph.Alert.Category | string | Alert category. | 
| MsGraph.Alert.Severity | string | Alert severity. | 
| MsGraph.Alert.CreatedDate | date | Alert creation date. | 
| MsGraph.Alert.EventDate | date | Alert event date. | 
| MsGraph.Alert.Status | string | Alert status. | 
| MsGraph.Alert.Vendor | string | Alert vendor. | 
| MsGraph.Alert.Provider | Unknown | Alert provider .| 

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
| closed_date_time | Time at which the alert was closed in the following string format - MM/DD/YYYY. | Optional | 
| comments | Analyst comments on the alert (for customer alert management). | Optional | 
| feedback | Analyst feedback on the alert. Possible values are: unknown, truePositive, falsePositive, benignPositive. | Optional | 
| status | Alert lifecycle status (stage). Possible values are: unknown, newAlert, inProgress, resolved. | Optional | 
| tags | User-definable labels that can be applied to an alert and can serve as filter conditions, for example "HVA", "SAW). | Optional | 
| vendor_information | Details about the security service vendor, for example Microsoft. | Required | 
| provider_information | Details about the security service vendor, for example Windows Defender ATP. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MsGraph.Alert.ID | string | Alert ID. | 
| MsGraph.Alert.Status | string | Alert status. | 
