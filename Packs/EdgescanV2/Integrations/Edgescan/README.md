Cloud-based continuous vulnerability management and penetration testing solution.
This integration was integrated and tested with version xx of Edgescan

## Configure Edgescan on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Edgescan.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | API Key |  | True |
    | Max number of incidents to fetch at once |  | False |
    | Fetch vulnerabilities with CVSS greater than | Fetch vulnerabilities with CVS score greater than. This can be a decimal point number. Disabled if empty | False |
    | Fetch vulnerabilities with risk more than | Disabled if empty | False |
    | First fetch time | How many days to fetch back on first run. It can be: 360 days, 12 months, 1 year, etc. | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Fetch vulnerabilities with CVSS with exact value | Fetch vulnerabilities with CVS score that exactly equals the provided value. This can be a decimal point number. Disabled if empty. | False |
    | Incidents Fetch Interval |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### edgescan-host-get-hosts
***
Get a list of all hosts


#### Base Command

`edgescan-host-get-hosts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.HostGetHosts | Unknown | List of all hosts | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-host-get
***
Get detailed information about a host.


#### Base Command

`edgescan-host-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The host id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.HostGet | Unknown | Detailed host information | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-host-get-export
***
Get a list of hosts in export format.


#### Base Command

`edgescan-host-get-export`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | The file format to export. Possible values are: json, csv, xlsx. Default is json. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile | Unknown | Export host information | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-host-get-query
***
Get a list of hosts by query


#### Base Command

`edgescan-host-get-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The asset ID. | Optional | 
| os_name | The Operating System name. | Optional | 
| label | The asset label. | Optional | 
| status | The asset status. | Optional | 
| id | The host id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.HostGetQuery | Unknown | The result of a host query | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-host-update
***
Update a host


#### Base Command

`edgescan-host-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| label | The host label. | Optional | 
| id | The host id to update. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.HostUpdate | Unknown | Information returned after host update | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-asset-get-assets
***
Get the full list of assets


#### Base Command

`edgescan-asset-get-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detail_level | The detail level of the metadata. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetGetAssets | Unknown | List of all assets | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-asset-get
***
Get asset details


#### Base Command

`edgescan-asset-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetGet | Unknown | Detailed information about an asset | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-asset-get-query
***
Query the asset database


#### Base Command

`edgescan-asset-get-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The asset ID. | Optional | 
| name | The asset name. | Optional | 
| hostname | The asset hostname. | Optional | 
| priority | Asset priority. | Optional | 
| type | Asset type. | Optional | 
| authenticated | Authentication status. | Optional | 
| host_count | Number of hosts. | Optional | 
| created_at | Creation date. | Optional | 
| updated_at | Last time updated at. | Optional | 
| location | Asset location. | Optional | 
| location_type | Location type of an asset. | Optional | 
| pci_enabled | PCI compliance status. | Optional | 
| last_host_scan | Last host scan date. | Optional | 
| network_access | Asset network access. | Optional | 
| current_assessment | Asset assesment. | Optional | 
| next_assessment_date | Asset next assesment date. | Optional | 
| active_licence | Asset license state. | Optional | 
| blocked_status | Asset lock status. | Optional | 
| last_assessment_date | Date of last asset assesment. | Optional | 
| asset_status | The asset status. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetGetQuery | Unknown | Output of an asset query | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-asset-create
***
Create an asset


#### Base Command

`edgescan-asset-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Asset ID. | Optional | 
| name | Asset name. | Optional | 
| priority | Asset priority. | Optional | 
| type | Asset type. | Optional | 
| authenticatied | Asset authentication status. | Optional | 
| tags | Asset tags. | Optional | 
| location_secifiers | Asset location specifiers. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetCreate | Unknown | Information about asset creation | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-asset-update
***
Update an asset


#### Base Command

`edgescan-asset-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Asset name. | Optional | 
| priority | Asset priority. | Optional | 
| type | Asset type. | Optional | 
| authenticatied | Asset authentication status. | Optional | 
| tags | Asset tags. | Optional | 
| location_secifiers | Asset location specifiers. | Optional | 
| id | The asset ID to update. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetUpdate | Unknown | Information about asset update | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-asset-delete
***
Delete an asset


#### Base Command

`edgescan-asset-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Asset name. | Optional | 
| priority | Asset priority. | Optional | 
| type | Asset type. | Optional | 
| authenticatied | Asset authentication status. | Optional | 
| tags | Asset tags. | Optional | 
| location_secifiers | Asset location specifiers. | Optional | 
| id | The asset id to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.AssetDelete | Unknown | Information about asset deletion | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-get-users
***
Get the full user list


#### Base Command

`edgescan-user-get-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserGetusers | Unknown | The list of all users | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-get
***
Get user details


#### Base Command

`edgescan-user-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user ID to get. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserGet | Unknown | Detailed user information | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-get-query
***
Query for a user


#### Base Command

`edgescan-user-get-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID. | Optional | 
| username | The username. | Optional | 
| phone_number | The user's phone number. | Optional | 
| phone_number_confirmed | User's phone number confirmation. | Optional | 
| mfa_enabled | User's Multi Factor Authentication Status. | Optional | 
| mfa_method | User's Multi Factor Authentication Method. | Optional | 
| email | User's E-Mail Address. | Optional | 
| email_confirmed | Email confirmation status. | Optional | 
| created_at | User creation date. | Optional | 
| updated_at | Last user update. | Optional | 
| is_super | Superuser status. | Optional | 
| account_locked | User lock status. | Optional | 
| lock_reason | User lock reason. | Optional | 
| lock_time | User lock time. | Optional | 
| last_login_time | User's last login time. | Optional | 
| last_password_reset_time | User's last password reset time. | Optional | 
| first_name | User's first name. | Optional | 
| last_name | User's last name. | Optional | 
| l | Result query limit. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserGetQuery | Unknown | Result of a user query | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-create
***
Create a user


#### Base Command

`edgescan-user-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username. | Optional | 
| email | User's E-Mail Address. | Optional | 
| first_name | User's first name. | Optional | 
| last_name | User's last name. | Optional | 
| phone_number | User's phone number. | Optional | 
| mfa_enabled | User's Multi Factor Authentication Status. | Optional | 
| mfa_method | User's Multi Factor Authentication method. | Optional | 
| is_super | Super user status. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserCreate | Unknown | Information about a created user | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-delete
***
Delete a user


#### Base Command

`edgescan-user-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserDelete | Unknown | Information about a deleted user | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-reset-password
***
Reset a user's password


#### Base Command

`edgescan-user-reset-password`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to reset the password for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserResetPassword | Unknown | Information about User password reset | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-reset-email
***
Reset a users password


#### Base Command

`edgescan-user-reset-email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to reset the email for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserResetEmail | Unknown | Information about User email reset. | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-lock-account
***
Lock a user


#### Base Command

`edgescan-user-lock-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to lock. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserLockAccount | Unknown | Information about the User lock | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-unlock-account
***
Unlock a user


#### Base Command

`edgescan-user-unlock-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to unlock. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserUnlockAccount | Unknown | Information about user unlock status | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-user-get-permissions
***
Get user's permissions


#### Base Command

`edgescan-user-get-permissions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The user id to get the permissions for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.UserGetPermissions | Unknown | The user permissions | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-vulnerabilities-get
***
Get the full list of vulnerabilities


#### Base Command

`edgescan-vulnerabilities-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EdgeScan.VulnerabilitiesGet | Unknown | The list of all Vulnerabilities | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-vulnerabilities-get-export
***
Get the full list of vulnerabilities for export


#### Base Command

`edgescan-vulnerabilities-get-export`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | The file format to export. Possible values are: json, csv, xlsx. Default is json. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile | Unknown | The vulnerabilities export list | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-vulnerabilities-get-details
***
Get vulnerability details


#### Base Command

`edgescan-vulnerabilities-get-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The vulnerability details to get details for. Possible values are: . | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.VulnerabilitiesGetDetails | Unknown | The vulnerability details | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-vulnerabilities-get-query
***
Run a vulnerability query


#### Base Command

`edgescan-vulnerabilities-get-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_tagged_with_any | Is asset tagged with any. | Optional | 
| risk_more_than | Is risk score more than provided. | Optional | 
| id | The vulnerability id. | Optional | 
| severity | The vulnerability severity. | Optional | 
| threat | The vulnerability threat level. | Optional | 
| asset_id | The asset_id associated with the vulnerability. | Optional | 
| asset_name | The asset name associated with the vulnerability. | Optional | 
| risk | The vulnerability risk level. | Optional | 
| cvss_score | The vulnerability CVSS score. | Optional | 
| cvss_vector | The vulnerability CVSS vector. | Optional | 
| cvss_v2_score | The vulnerability CVSS v2 score. | Optional | 
| cvss_version | The CVSS version to query for. | Optional | 
| altered_score | true/false. | Optional | 
| date_opened | The date on which the vulnerability was opened. | Optional | 
| date_closed | The date on which the vulnerability was closed. | Optional | 
| status | The status of the vulnerability. | Optional | 
| pci_compliance_status | The vulnerability pci complience status. | Optional | 
| location | The vulnerability location. | Optional | 
| location_specifier_id | The vulnerability location specifier id. | Optional | 
| confidence | The vulnerability confidence level. | Optional | 
| label | The vulnerability label. | Optional | 
| layer | The vulnerability level. | Optional | 
| last_pci_exception | The vulnerability last PCI exception. | Optional | 
| updated_at | The vulnerability updated at time. | Optional | 
| created_at | The vulnerability created at time. | Optional | 
| name | The vulnerability name. | Optional | 
| date_opened_after | The date the vulnerability was opened after i.e. "2021-04-01T14:27:10.900Z". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.VulnerabilitiesGetQuery | Unknown | The result of a vulnerability query | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-vulnerabilities-retest
***
Retest a vulnerability


#### Base Command

`edgescan-vulnerabilities-retest`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The vulnerability id to retest. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.VulnerabilitiesRetest | Unknown | The Vulnerability retest result | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-vulnerabilities-risk-accept
***
Rish accept a vulnerability


#### Base Command

`edgescan-vulnerabilities-risk-accept`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The risk accept value. Default is true. | Optional | 
| id | The vulnerability id to risk accept. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Edgescan.VulnerabilitiesRiskAccept | Unknown | The vulnerability retest result | 


#### Command Example
``` ```

#### Human Readable Output



### edgescan-vulnerabilities-add-annotation
***
This command adds a text annotation to a vulnerability


#### Base Command

`edgescan-vulnerabilities-add-annotation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the vulnerability to add the annotation to. | Required | 
| text | The text of the annotation to add. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnnotationAdd | Unknown | The annotation creation output | 


#### Command Example
``` ```

#### Human Readable Output


