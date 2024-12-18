This integration allows to create incidents based on Vectra Accounts/Hosts/Detections objects.
This integration was integrated and tested with version 7.1 of Vectra Detect

## Use cases

1. Fetch accounts, hosts and detections from Vectra Detect.
2. Bi-Directional mirroring for accounts and hosts.
3. List and describe accounts, hosts, detections, and users.
4. List, describe, create, and resolve assignments for accounts and hosts.
5. List, describe, and create assignment outcomes.
6. List, create, update, and delete notes for accounts, hosts, and detections.
7. List, create, and remove tags for accounts, hosts, and detections.
8. List, assign, and unassign members in group.
9. Mark and unmark detection as fixed.
10. Mark all detections as fixed for accounts and hosts. 
11. Get detection's PCAP file.
12. Clean up all incidents in Cortex XSOAR by closing duplicate incidents from Vectra Detect.

## Configure Vectra Detect on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Vectra Detect.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Vectra Detect FQDN or IP | Enter the FQDN or IP to reach the Vectra Detect API. \(e.g. "my-vectra-box.local" or "192.168.1.1"\) | True |
    | API Token | Enter the API token that can be retrieved from the Vectra UI &amp;gt; My Profile &amp;gt; General \(tab\) &amp;gt; API Token. You can also use the XSOAR credentials wallet to store it. In that case, the token should be the password. | True |
    | API Token |  | True |
    | Trust any certificate (not secure) | When checked, no SSL certificates check will be done when interacting with the Vectra Detect API. It's insecure. \(Default - unchecked\) | False |
    | Use system proxy settings | Use the system proxy settings to reach with the Vectra Detect API. | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | First fetch timestamp | The date or relative timestamp from which to begin fetching entities.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2024, 01 Aug 2024 04:45:33, 2024-07-17T14:05:44Z. \(default - 7 days\) | False |
    | Mirroring Direction | The mirroring direction in which to mirror the account and host. You can mirror "Incoming" \(from Vectra to Cortex XSOAR\), "Outgoing" \(from Cortex XSOAR to Vectra\), or in both directions. | False |
    | Mirror tag for notes | The tag value should be used to mirror the account and host note by adding the same tag in the notes. | False |
    | Entity types to fetch | Choose what to fetch - Accounts and/or Hosts and/or Detections. \(Default - Accounts,Hosts\) | False |
    | Tags | Only Accounts or Hosts that contain any of the tags specified will be fetched.<br/><br/>Note: For the partial match of the tag, use '\*' at the start and end of word \(Only a single word is allowed\). Ex. \*MDR\*. | False |
    | Detection Category | Filter the detections belonging to a specified category displayed as part of layout.<br/><br/>Note: This filter applies on the 'Vectra Account' and 'Vectra Host' incident type. | False |
    | Detection Type | Filter the detections belonging to a specified type displayed as part of layout.<br/><br/>Note: This filter applies on the 'Vectra Account' and 'Vectra Host' incident type. |  |
    | Hosts fetch query | Only "active" Hosts matching this fetch query will be fetched. Will be used only if "Hosts" is selected in the "Entity types to fetch". \(default - host.threat:&gt;=50\) | False |
    | Accounts fetch query | Only "active" Accounts matching this fetch query will be fetched. Will be used only if "Accounts" is selected in the "Entity types to fetch". \(default - account.threat:&gt;=50\) | False |
    | Detections fetch query | Only "active" Detections matching this fetch query will be fetched. Will be used only if "Detections" is selected in the "Entity types to fetch". \(default - detection.threat:&gt;=50 AND detection.certainty:&gt;=50\) | False |
    | Max created incidents per fetch | The maximum number of new incidents to create per fetch. This value would be split between selected "Entity types to fetch". If the value is greater than 200, it will be considered as 200. The maximum is 200. \(Default - 50\) | False |
    | Advanced: Minutes to look back when fetching | Use this parameter to determine how long backward to look in the search for incidents that were created before the last run time and did not match the query when they were created. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Configuration for fetching Vectra Account or Vectra Host as a Cortex XSOAR incident

To fetch Vectra Account or Vectra Host as a Cortex XSOAR incident:

1. Select **Fetches incidents**.
2. Under Classifier, select "Vectra Detect".
3. Under Incident type, select "N/A".
4. Under Mapper (incoming), select "Vectra Detect - Incoming Mapper" for default mapping.
5. Enter connection parameters. (Vectra Detect FQDN or IP, API Token)
6. Select SSL certificate validation and Proxy if required.
7. Update "Max created incidents per fetch" & "First fetch timestamp" based on your requirements.
8. Select the Incident Mirroring Direction:
    1. Incoming - Mirrors changes from the Vectra into the Cortex XSOAR incident.
    2. Outgoing - Mirrors changes from the Cortex XSOAR incident to the Vectra.
    3. Incoming And Outgoing - Mirrors changes both Incoming and Outgoing directions on incidents.
9. Enter the relevant tag name for mirror notes.
    **Note:** This value is mapped to the dbotMirrorTags incident field in Cortex XSOAR, which defines how Cortex XSOAR handles notes when you tag them in the War Room. This is required for mirroring notes from Cortex XSOAR to Vectra.
10. Provide the filter parameter "Tags”, to filter entities by specific tag/s for fetch type account and host.
11. Provide the filter parameter "Detection Category” and "Detection Type", to filter detections by the specified category and type for fetch type account and host.

**Notes for mirroring:**

- The mirroring is strictly tied to incident types "Vectra Account" and "Vectra Host", as well as the incoming mapper "Vectra Detect - Incoming Mapper". If you want to change or use a custom incident type/mapper, ensure that related changes are also present.
- The mirroring settings apply only for incidents that are fetched after applying the settings.
- Any tags removed from the Vectra Account or Vectra Host will not be removed in the Cortex XSOAR incident, as Cortex XSOAR doesn't allow the removal of the tags field via the backend. However, tags removed from the Cortex XSOAR incident UI will be removed from the Vectra Account or Vectra Host.
- New notes from the Cortex XSOAR incident will be created as notes in the Vectra Account or Vectra Host. Updates to existing notes in the Cortex XSOAR incident will not be reflected in the Vectra Account or Vectra Host.
- New notes from the Vectra Account or Vectra Host will be created as notes in the Cortex XSOAR incident. Updates to existing notes in the Vectra Account or Vectra Host will create new notes in the Cortex XSOAR incident.
- If a closed Cortex XSOAR incident is tied to a specific Account or Vectra Host and new detections for that Account or Vectra Host arise or existing detections become active again, the incident will be automatically reopened.
- When a Cortex XSOAR incident is closed but there are still active detections on the Vectra side, and the Account or Vectra Host is subsequently updated, the corresponding Cortex XSOAR incident for that entity will be reopened.
- If a Cortex XSOAR incident is reopened and the corresponding entity has an assignment in Vectra, the assignment will be removed from Vectra.
- If you want to use the mirror mechanism and you're using custom mappers, then the incoming mapper must contain the following fields: dbotMirrorDirection, dbotMirrorId, dbotMirrorInstance, and dbotMirrorTags.
- To use a custom mapper, you must first duplicate the mapper and update the fields in the copy of the mapper. (Refer to the "Create a custom mapper consisting of the default Vectra Detect - Incoming Mapper" section for more information.)
- Following new fields are introduced in the response of the incident to enable the mirroring:
  - **mirror_direction:** This field determines the mirroring direction for the incident. It is a required field for Cortex XSOAR to enable mirroring support.
  - **mirror_tags:** This field determines what would be the tag needed to mirror the Cortex XSOAR entry out to Vectra. It is a required field for XSOAR to enable mirroring support.
  - **mirror_instance:** This field determines from which instance the Cortex XSOAR incident was created. It is a required field for Cortex XSOAR to enable mirroring support.

#### Cleanup Duplicate Incidents

- Use the **Close All Duplicate XSOAR Incidents - Vectra Detect** playbook to clean up duplicate incidents. You can use **VectraDetectCloseDuplicateIncidents** script individually to clean up duplicate incidents.
- You can also schedule a job with **Close All Duplicate XSOAR Incidents - Vectra Detect** playbook in Cortex XSOAR to clean up incidents periodically. Refer to [this Cortex XSOAR documentation](https://xsoar.pan.dev/docs/incidents/incident-jobs) for more information.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### vectra-search-accounts
***
Returns a list of Account objects. All search attributes will be cumulative unless you're using the search_query_only one, in that case, only this one will be taken into account.


#### Base Command

`vectra-search-accounts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| min_id | Returns Accounts with an ID greater than or equal to the specified ID. | Optional | 
| max_id | Returns Accounts with an ID less than or equal to the specified ID. | Optional | 
| min_threat | Returns Accounts with a threat score greater than or equal to the specified score. | Optional | 
| max_threat | Returns Accounts with a threat score less than or equal to the specified score. | Optional | 
| min_certainty | Returns Accounts with a certainty score greater than or equal to the specified score. | Optional | 
| max_certainty | Returns Accounts with a certainty score less than or equal to the specified score. | Optional | 
| state | Filters by state ('active', 'inactive'). Possible values are: active, inactive. | Optional | 
| search_query | Search query in Lucene query syntax. | Optional | 
| search_query_only | Use specifically this search query. Compared to "search_query" where default arguments are appended. | Optional | 
| min_privilege_level | Returns entries with a  privilege level greater than or equal to the specified score. | Optional | 
| max_privilege_level | Returns entries with a  privilege level greater than or equal to the specified score. | Optional | 
| privilege_category | Filters by the privilege category ("low", "medium", "high") provided. | Optional | 
| tags | Filters by a tag or a comma-separated list tags. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Account.Assignee | String | Vectra user account this Account is assigned to | 
| Vectra.Account.AssignedDate | String | Assignment date | 
| Vectra.Account.CertaintyScore | Number | Account certainty score | 
| Vectra.Account.ID | Number | Account ID \(unique\) | 
| Vectra.Account.LastDetectionTimestamp | String | Last time a detection linked to this account has been seen | 
| Vectra.Account.PrivilegeLevel | Number | Account privilege level \(from 1 to 10\) | 
| Vectra.Account.PrivilegeCategory | String | Account privilege category \(Either 'Low', 'Medium' or 'High' - Privilege levels of 1-2 &gt; 'Low', 3-7 &gt; 'Medium', 8-10 &gt; 'High'\) | 
| Vectra.Account.Severity | String | Account severity according to scores \('Low', 'Medium', 'High', 'Critical'\) | 
| Vectra.Account.State | String | Account state \('active', 'inactive'\) | 
| Vectra.Account.Tags | String | Account tags | 
| Vectra.Account.ThreatScore | Number | Account threat score | 
| Vectra.Account.Type | String | Account type \('kerberos' or 'o365'\) | 
| Vectra.Account.URL | String | Account URL to pivot to Vectra UI | 
| Vectra.Account.Name | String | The username of the account | 

### vectra-search-hosts
***
Returns a list of Host objects. All search attributes will be cumulative unless you're using the search_query_only one, in that case, only this one will be taken into account.


#### Base Command

`vectra-search-hosts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| min_id | Returns Hosts with an ID greater than or equal to the specified ID. | Optional | 
| max_id | Returns Hosts with an ID less than or equal to the specified ID. | Optional | 
| min_threat | Returns Hosts with a threat score greater than or equal to the specified score. | Optional | 
| max_threat | Returns Hosts with a threat score less than or equal to the specified score. | Optional | 
| min_certainty | Returns Hosts with a certainty score greater than or equal to the specified score. | Optional | 
| max_certainty | Returns Hosts with a certainty score less than or equal to the specified score. | Optional | 
| state | Filters by state ('active', 'inactive'). Possible values are: active, inactive. | Optional | 
| search_query | Search query in Lucene query syntax. | Optional | 
| search_query_only | Use specifically this search query. Compared to "search_query" where default arguments are appended. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Host.Assignee | String | Vectra user account this Host is assigned to | 
| Vectra.Host.AssignedDate | String | Assignment date | 
| Vectra.Host.CertaintyScore | Number | Host certainty score | 
| Vectra.Host.HasActiveTraffic | Boolean | Whether this Host has active traffic | 
| Vectra.Host.Hostname | String | Host name | 
| Vectra.Host.ID | Number | Host ID \(Unique\) | 
| Vectra.Host.IP | String | Host IP address | 
| Vectra.Host.IsKeyAsset | Boolean | Whether this Host is seen as a key asset | 
| Vectra.Host.IsTargetingKeyAsset | Boolean | Whether this Host is targeting a key asset | 
| Vectra.Host.PrivilegeLevel | Number | Host privilege level \(from 1 to 10\) | 
| Vectra.Host.PrivilegeCategory | String | Host privilege category. \(Either 'Low', 'Medium' or 'High' - Privilege levels of 1-2 &gt; 'Low', 3-7 &gt; 'Medium', 8-10 &gt; 'High'\) | 
| Vectra.Host.ProbableOwner | String | Host probable owner | 
| Vectra.Host.SensorLUID | String | Sensor LUID that saw this Host | 
| Vectra.Host.SensorName | String | Sensor Name that saw this Host | 
| Vectra.Host.Sensor | String | Sensor details that have seen this Host | 
| Vectra.Host.Severity | String | Host severity according to scores \('Low', 'Medium', 'High', 'Critical'\) | 
| Vectra.Host.State | String | Host state \('active', 'inactive'\) | 
| Vectra.Host.Tags | String | Host tags | 
| Vectra.Host.ThreatScore | Number | Host threat score | 
| Vectra.Host.URL | String | Host URL to pivot to Vectra UI | 

### vectra-search-detections
***
Returns a list of Detection objects. All search attributes will be cumulative unless you're using the search_query_only one, in that case, only this one will be taken into account.


#### Base Command

`vectra-search-detections`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| min_id | Returns Detections with an ID greater than or equal to the specified ID. | Optional | 
| max_id | Returns Detections with an ID less than or equal to the specified ID. | Optional | 
| min_threat | Returns Detections with a threat score greater than or equal to the specified score. | Optional | 
| max_threat | Returns Detections with a threat score less than or equal to the specified score. | Optional | 
| min_certainty | Returns Detections with a certainty score greater than or equal to the specified score. | Optional | 
| max_certainty | Returns Detections with a certainty score less than or equal to the specified score. | Optional | 
| state | Filters by state ('active', 'inactive'). Possible values are: active, inactive. | Optional | 
| search_query | Search query in Lucene query syntax. | Optional | 
| search_query_only | Use specifically this search query. Compared to "search_query" where default arguments are appended. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Assignee | String | Vectra user account this detection is assigned to | 
| Vectra.Detection.AssignedDate | String | Assignment date | 
| Vectra.Detection.Category | String | Detection category \(Lateral, Exfil, ...\) | 
| Vectra.Detection.CertaintyScore | Number | Detection certainty score | 
| Vectra.Detection.Description | String | Detection description | 
| Vectra.Detection.DestinationIPs | String | Detection destination IPs | 
| Vectra.Detection.DestinationPorts | String | Detection destination ports | 
| Vectra.Detection.FirstTimestamp | String | First time this detection has been seen | 
| Vectra.Detection.ID | Number | Detection ID \(unique\) | 
| Vectra.Detection.IsTargetingKeyAsset | Boolean | Whether this detection is targeting a key asset | 
| Vectra.Detection.LastTimestamp | String | Last time this detection has been seen | 
| Vectra.Detection.Name | String | The name of the detection. Would be a user defined name if this detection is triaged or the default type name instead | 
| Vectra.Detection.Severity | String | Detection severity according to scores \('Low', 'Medium', 'High', 'Critical'\) | 
| Vectra.Detection.SensorLUID | String | Sensor LUID that saw this detection | 
| Vectra.Detection.SensorName | String | Sensor name that saw this detection. | 
| Vectra.Detection.SourceAccountID | String | Account ID relating to this detection | 
| Vectra.Detection.SourceHostID | String | Host ID relating to this detection | 
| Vectra.Detection.SourceIP | String | Source IP relating to this detection | 
| Vectra.Detection.State | String | Detection state \('active', 'inactive'\) | 
| Vectra.Detection.Tags | String | Detection tags | 
| Vectra.Detection.ThreatScore | Number | Detection threat score | 
| Vectra.Detection.TriageRuleID | String | Triage rule ID related to this detection | 
| Vectra.Detection.Type | String | Detection type \(Brute Force, Port Sweep, ...\) | 
| Vectra.Detection.URL | String | Detection URL to pivot to Vectra UI | 

### vectra-search-assignments
***
Return a list of assignments. By default already resolved assignment are not returned.


#### Base Command

`vectra-search-assignments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | Filters by accounts IDs. | Optional | 
| assignee_ids | Filters by assignees IDs. | Optional | 
| host_ids | Filters by hosts IDs. | Optional | 
| outcome_ids | Filters by outcomes IDs. | Optional | 
| resolved | Filters by resolution state. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Assignment.AccountID | Number | Account ID this assignment is linked to | 
| Vectra.Assignment.AssignedBy | String | Who lastly assigned this assignment | 
| Vectra.Assignment.AssignedDate | String | When this assignment was lastly assigned | 
| Vectra.Assignment.AssignedTo | String | To who this assignment is assigned | 
| Vectra.Assignment.HostID | String | Host ID this assignment is linked to | 
| Vectra.Assignment.ID | Number | Assignment ID \(unique\) | 
| Vectra.Assignment.IsResolved | Boolean | Is this assignment resolved | 
| Vectra.Assignment.OutcomeCategory | String | Assignment Outcome category | 
| Vectra.Assignment.OutcomeTitle | String | Assignment Outcome title | 
| Vectra.Assignment.TriagedDetections | String | List of Detection that have been triaged with the resolution | 
| Vectra.Assignment.TriagedAs | String | Name of the triage rule if any | 
| Vectra.Assignment.ResolvedBy | String | Who resolved this assignment | 
| Vectra.Assignment.ResolvedDate | string | When this assignment was resolved | 

### vectra-search-users
***
Returns a list of Vectra Users. All search attributes will be cumulative.


#### Base Command

`vectra-search-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Filters by user name. | Optional | 
| role | Filters by user role. | Optional | 
| type | Filters by type ('Local', 'SAML', ...). Possible values are: local, SAML. | Optional | 
| last_login_datetime | Filters for Users that logged in since the given datetime. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.User.Email | String | User's email address | 
| Vectra.User.ID | Number | User ID \(unique\) | 
| Vectra.User.Role | String | User's role | 
| Vectra.User.Type | String | User type \('Local', 'SAML', ...\) | 
| Vectra.User.Username | String | Username | 
| Vectra.User.LastLoginDate | String | User's last login datetime | 

### vectra-search-outcomes
***
Returns a list of assignment outcomes.


#### Base Command

`vectra-search-outcomes`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Outcome.IsBuiltIn | String | Is this Outcome a builtin Outcome | 
| Vectra.Outcome.Category | String | Outcome's category \('False Positive', 'Benign True Positive', 'Malicious True Positive'\) | 
| Vectra.Outcome.ID | Number | Outcome ID \(unique\) | 
| Vectra.Outcome.Title | String | Outcome title | 

### vectra-account-describe
***
Returns a single Account details


#### Base Command

`vectra-account-describe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Account ID you want to get details on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Account.Assignee | String | Vectra user account this Account is assigned to | 
| Vectra.Account.AssignedDate | String | Assignment date | 
| Vectra.Account.CertaintyScore | Number | Account certainty score | 
| Vectra.Account.ID | Number | Account ID \(unique\) | 
| Vectra.Account.LastDetectionTimestamp | String | Last time a detection linked to this account has been seen | 
| Vectra.Account.PrivilegeLevel | Number | Account privilege level \(from 1 to 10\) | 
| Vectra.Account.PrivilegeCategory | String | Account privilege category \(Either 'Low', 'Medium' or 'High' - Privilege levels of 1-2 &gt; 'Low', 3-7 &gt; 'Medium', 8-10 &gt; 'High'\) | 
| Vectra.Account.Severity | String | Account severity according to scores \('Low', 'Medium', 'High', 'Critical'\) | 
| Vectra.Account.State | String | Account state \('active', 'inactive'\) | 
| Vectra.Account.Tags | String | Account tags | 
| Vectra.Account.ThreatScore | Number | Account threat score | 
| Vectra.Account.Type | String | Account type \('kerberos' or 'o365'\) | 
| Vectra.Account.URL | String | Account URL to pivot to Vectra UI | 
| Vectra.Account.Name | String | The username of the account | 

### vectra-account-add-tags
***
Add tags to an Account


#### Base Command

`vectra-account-add-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Account ID you want to add tags on. | Optional | 
| tags | The tags list (comma separated). | Optional | 


#### Context Output

There is no context output for this command.
### vectra-account-del-tags
***
Delete tags from an Account


#### Base Command

`vectra-account-del-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Account ID you want to del tags from. | Optional | 
| tags | The tags list (comma separated). | Optional | 


#### Context Output

There is no context output for this command.
### vectra-account-tag-list

***
Returns a list of tags for a specified account.

#### Base Command

`vectra-account-tag-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the ID of the account. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Account.ID | Number | ID of the account associated with the tags. | 
| Vectra.Account.Tags | String | Tags associated to the account. | 

#### Command example
```!vectra-account-tag-list id="2" ```

#### Context Example
```json
{
    "Vectra.Account": {
        "ID": 2,
        "Tags": [
            "note",
            "tag_from_xsoar",
            "tag_from_vectra"
        ]
    }
}
```

#### Human Readable Output

>##### List of tags: **note**, **tag_from_xsoar**, **tag_from_vectra**

### vectra-account-note-add

***
Add a note to the account.

#### Base Command

`vectra-account-note-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Specify the ID of the account. | Required | 
| note | Note to be added in the specified account_id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Account.Notes.account_id | Number | ID of the account associated with the note. | 
| Vectra.Account.Notes.note_id | Number | ID of the note. | 
| Vectra.Account.Notes.date_created | Date | Date when the note was created. | 
| Vectra.Account.Notes.date_modified | Date | Date when the note was last modified. | 
| Vectra.Account.Notes.created_by | String | User who created the note. | 
| Vectra.Account.Notes.modified_by | String | User who last modified the note. | 
| Vectra.Account.Notes.note | String | Content of the note. | 

#### Command example
```!vectra-account-note-add account_id="2" note="test note" ```

#### Context Example
```json
{
    "Vectra.Account.Notes": {
        "date_created": "2024-07-10T07:30:58.574942Z",
        "created_by": "xsoar",
        "note": "test note",
        "note_id": 1959,
        "account_id": 2
    }
}
```

#### Human Readable Output

>##### The note has been successfully added to the account.
>Returned Note ID: **1959**


### vectra-account-note-update

***
Update a note in the account.

#### Base Command

`vectra-account-note-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Specify the ID of the account. | Required | 
| note_id | Specify the ID of the note.<br/><br/>Note: Use the vectra-account-note-list command to get note_id. | Required | 
| note | Note to be updated for the specified note_id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Account.Notes.account_id | Number | ID of the account associated with the note. | 
| Vectra.Account.Notes.note_id | Number | ID of the note. | 
| Vectra.Account.Notes.date_created | Date | Date when the note was created. | 
| Vectra.Account.Notes.date_modified | Date | Date when the note was last modified. | 
| Vectra.Account.Notes.created_by | String | User who created the note. | 
| Vectra.Account.Notes.modified_by | String | User who last modified the note. | 
| Vectra.Account.Notes.note | String | Content of the note. | 

#### Command example
```!vectra-account-note-update account_id="2" note_id="1959" note="updated test note"```

#### Context Example
```json
{
    "Vectra.Account.Notes": {
        "date_created": "2024-07-10T07:30:58.574942Z",
        "date_modified": "2024-07-12T06:42:29.546835Z",
        "created_by": "xsoar",
        "modified_by": "xsoar",
        "note": "updated test note",
        "note_id": 1959,
        "account_id": 2
    }
}
```

#### Human Readable Output

>##### The note has been successfully updated in the account.


### vectra-account-note-remove

***
Remove a note from the account.

#### Base Command

`vectra-account-note-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Specify the ID of the account. | Required | 
| note_id | Specify the ID of the note.<br/><br/>Note: Use the vectra-account-note-list command to get note_id. | Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!vectra-account-note-remove account_id="2" note_id="1959"```

#### Human Readable Output

>##### The note has been successfully removed from the account.


### vectra-account-note-list

***
List all notes of the specific account.

#### Base Command

`vectra-account-note-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Specify the ID of the account. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Account.Notes.account_id | Number | ID of the account associated with the note. | 
| Vectra.Account.Notes.note_id | Number | ID of the note. | 
| Vectra.Account.Notes.date_created | Date | Date when the note was created. | 
| Vectra.Account.Notes.date_modified | Date | Date when the note was last modified. | 
| Vectra.Account.Notes.created_by | String | User who created the note. | 
| Vectra.Account.Notes.modified_by | String | User who last modified the note. | 
| Vectra.Account.Notes.note | String | Content of the note. | 

#### Command example
```!vectra-account-note-list account_id="2"```

#### Context Example
```json
{
    "Vectra.Account.Notes": [
        {
            "date_created": "2024-07-10T05:40:31Z",
            "date_modified": "2024-07-16T12:56:30Z",
            "created_by": "xsoar",
            "modified_by": "xsoar",
            "note": "updated_note",
            "note_id": 1959,
            "account_id": 2
        },
        {
            "date_created": "2024-07-08T07:11:49Z",
            "created_by": "xsoar",
            "note": "Here comes your note TEST",
            "note_id": 1906,
            "account_id": 2
        }
    ]
}
```
#### Human Readable Output

>##### Notes Table
>|Note ID|Note|Created By|Created Date|Modified By|Modified Date|
>|---|---|---|---|---|---|
>| 1959 | updated_note | xsoar | 2024-07-10T05:40:31Z | xsoar | 2024-07-16T12:56:30Z |
>| 1906 | Here comes your note TEST | xsoar | 2024-07-08T07:11:49Z |  |  |


### vectra-account-markall-detections-asfixed

***
Mark active detections as fixed by providing the ID of the account in the argument.

#### Base Command

`vectra-account-markall-detections-asfixed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Provide an account ID. | Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!vectra-account-markall-detections-asfixed account_id=109```

#### Human Readable Output
>The active detections of the provided account have been successfully marked as fixed.


### vectra-host-describe
***
Returns a single Host details


#### Base Command

`vectra-host-describe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Host ID you want to get details on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Host.Assignee | String | Vectra user account this Host is assigned to | 
| Vectra.Host.AssignedDate | String | Assignment date | 
| Vectra.Host.CertaintyScore | Number | Host certainty score | 
| Vectra.Host.HasActiveTraffic | Boolean | Whether this Host has active traffic | 
| Vectra.Host.Hostname | String | Host name | 
| Vectra.Host.ID | Number | Host ID \(Unique\) | 
| Vectra.Host.IP | String | Host IP address | 
| Vectra.Host.IsKeyAsset | Boolean | Whether this Host is seen as a key asset | 
| Vectra.Host.IsTargetingKeyAsset | Boolean | Whether this Host is targeting a key asset | 
| Vectra.Host.PrivilegeLevel | Number | Host privilege level \(from 1 to 10\) | 
| Vectra.Host.PrivilegeCategory | String | Host privilege category. \(Either 'Low', 'Medium' or 'High' - Privilege levels of 1-2 &gt; 'Low', 3-7 &gt; 'Medium', 8-10 &gt; 'High'\) | 
| Vectra.Host.ProbableOwner | String | Host probable owner | 
| Vectra.Host.SensorLUID | String | Sensor LUID that saw this Host | 
| Vectra.Host.SensorName | String | Sensor Name that saw this Host | 
| Vectra.Host.Sensor | String | Sensor details that have seen this Host | 
| Vectra.Host.Severity | String | Host severity according to scores \('Low', 'Medium', 'High', 'Critical'\) | 
| Vectra.Host.State | String | Host state \('active', 'inactive'\) | 
| Vectra.Host.Tags | String | Host tags | 
| Vectra.Host.ThreatScore | Number | Host threat score | 
| Vectra.Host.URL | String | Host URL to pivot to Vectra UI | 

### vectra-host-add-tags
***
Add tags to an Host


#### Base Command

`vectra-host-add-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Host ID you want to add tags on. | Optional | 
| tags | The tags list (comma separated). | Optional | 


#### Context Output

There is no context output for this command.
### vectra-host-del-tags
***
Delete tags from an Host


#### Base Command

`vectra-host-del-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Host ID you want to del tags from. | Optional | 
| tags | The tags list (comma separated). | Optional | 


#### Context Output

There is no context output for this command.
### vectra-host-tag-list

***
Returns a list of tags for a specified host.

#### Base Command

`vectra-host-tag-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the ID of the host. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Host.ID | Number | ID of the host associated with the tags. | 
| Vectra.Host.Tags | String | Tags associated to the host. | 

#### Command example
```!vectra-host-tag-list id="2" ```

#### Context Example
```json
{
    "Vectra.Host": {
        "ID": 2,
        "Tags": [
            "note",
            "tag_from_xsoar",
            "tag_from_vectra"
        ]
    }
}
```

#### Human Readable Output

>##### List of tags: **note**, **tag_from_xsoar**, **tag_from_vectra**

### vectra-host-note-add

***
Add a note to the host.

#### Base Command

`vectra-host-note-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | Specify the ID of the host. | Required | 
| note | Note to be added in the specified host_id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Host.Notes.host_id | Number | ID of the host associated with the note. | 
| Vectra.Host.Notes.note_id | Number | ID of the note. | 
| Vectra.Host.Notes.date_created | Date | Date when the note was created. | 
| Vectra.Host.Notes.date_modified | Date | Date when the note was last modified. | 
| Vectra.Host.Notes.created_by | String | User who created the note. | 
| Vectra.Host.Notes.modified_by | String | User who last modified the note. | 
| Vectra.Host.Notes.note | String | Content of the note. | 

#### Command example
```!vectra-host-note-add host_id="5" note="test note" ```

#### Context Example
```json
{
    "Vectra.Host.Notes": {
        "date_created": "2024-07-10T07:31:58.574942Z",
        "created_by": "xsoar",
        "note": "test note",
        "note_id": 1960,
        "host_id": 5
    }
}
```

#### Human Readable Output

>##### The note has been successfully added to the host.
>Returned Note ID: **1960**

### vectra-host-note-update

***
Update a note in the host.

#### Base Command

`vectra-host-note-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | Specify the ID of the host. | Required | 
| note_id | Specify the ID of the note.<br/><br/>Note: Use the vectra-host-note-list command to get note_id. | Required | 
| note | Note to be updated for the specified note_id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Host.Notes.host_id | Number | ID of the host associated with the note. | 
| Vectra.Host.Notes.note_id | Number | ID of the note. | 
| Vectra.Host.Notes.date_created | Date | Date when the note was created. | 
| Vectra.Host.Notes.date_modified | Date | Date when the note was last modified. | 
| Vectra.Host.Notes.created_by | String | User who created the note. | 
| Vectra.Host.Notes.modified_by | String | User who last modified the note. | 
| Vectra.Host.Notes.note | String | Content of the note. | 

#### Command example
```!vectra-account-note-update host_id="7" note_id="1960" note="updated test note"```

#### Context Example
```json
{
    "Vectra.Host.Notes": {
        "date_created": "2024-07-10T07:31:58.574942Z",
        "date_modified": "2024-07-12T06:44:29.546835Z",
        "created_by": "xsoar",
        "modified_by": "xsoar",
        "note": "updated test note",
        "note_id": 1960,
        "host_id": 7
    }
}
```

#### Human Readable Output

>##### The note has been successfully updated in the host.


### vectra-host-note-remove

***
Remove a note from the host.

#### Base Command

`vectra-host-note-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | Specify the ID of the host. | Required | 
| note_id | Specify the ID of the note.<br/><br/>Note: Use the vectra-host-note-list command to get note_id. | Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!vectra-host-note-remove host_id="7" note_id="1960"```

#### Human Readable Output

>##### The note has been successfully removed from the host.


### vectra-host-note-list

***
List all notes of the specific host.

#### Base Command

`vectra-host-note-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | Specify the ID of the host. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Host.Notes.host_id | Number | ID of the host associated with the note. | 
| Vectra.Host.Notes.note_id | Number | ID of the note. | 
| Vectra.Host.Notes.date_created | Date | Date when the note was created. | 
| Vectra.Host.Notes.date_modified | Date | Date when the note was last modified. | 
| Vectra.Host.Notes.created_by | String | User who created the note. | 
| Vectra.Host.Notes.modified_by | String | User who last modified the note. | 
| Vectra.Host.Notes.note | String | Content of the note. | 

#### Command example
```!vectra-host-note-list host_id="7"```

#### Context Example
```json
{
    "Vectra.Host.Notes": [
        {
            "date_created": "2024-07-11T07:32:31Z",
            "created_by": "xsoar",
            "note": "test note",
            "note_id": 1960,
            "host_id": 7
        },
        {
            "date_created": "2024-07-11T06:23:07Z",
            "created_by": "cds_xsoar",
            "note": "test note",
            "note_id": 1982,
            "host_id": 7
        }
    ]
}
```
#### Human Readable Output

>##### Notes Table
>|Note ID|Note|Created By|Created Date|
>|---|---|---|---|
>| 1960 | test note | xsoar | 2024-07-11T07:32:31Z |
>| 1982 | test note | cds_xsoar | 2024-07-11T06:23:07Z |


### vectra-host-markall-detections-asfixed

***
Mark active detections as fixed by providing ID of the host in the argument.

#### Base Command

`vectra-host-markall-detections-asfixed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | Provide a host ID. | Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!vectra-host-markall-detections-asfixed host_id=23176```

#### Human Readable Output
>The active detections of the provided host have been successfully marked as fixed.


### vectra-detection-describe
***
Returns a single detection details


#### Base Command

`vectra-detection-describe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Detection ID you want to get details on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Assignee | String | Vectra user account this detection is assigned to | 
| Vectra.Detection.AssignedDate | String | Assignment date | 
| Vectra.Detection.Category | String | Detection category \(Lateral, Exfil, ...\) | 
| Vectra.Detection.CertaintyScore | Number | Detection certainty score | 
| Vectra.Detection.Description | String | Detection description | 
| Vectra.Detection.DestinationIPs | String | Detection destination IPs | 
| Vectra.Detection.DestinationPorts | String | Detection destination ports | 
| Vectra.Detection.FirstTimestamp | String | First time this detection has been seen | 
| Vectra.Detection.ID | Number | Detection ID \(unique\) | 
| Vectra.Detection.IsTargetingKeyAsset | Boolean | Whether this detection is targeting a key asset | 
| Vectra.Detection.LastTimestamp | String | Last time this detection has been seen | 
| Vectra.Detection.Name | String | The name of the detection. Would be a user defined name if this detection is triaged or the default type name instead | 
| Vectra.Detection.Severity | String | Detection severity according to scores \('Low', 'Medium', 'High', 'Critical'\) | 
| Vectra.Detection.SensorLUID | String | Sensor LUID that saw this detection | 
| Vectra.Detection.SensorName | String | Sensor name that saw this detection. | 
| Vectra.Detection.SourceAccountID | String | Account ID relating to this detection | 
| Vectra.Detection.SourceHostID | String | Host ID relating to this detection | 
| Vectra.Detection.SourceIP | String | Source IP relating to this detection | 
| Vectra.Detection.State | String | Detection state \('active', 'inactive'\) | 
| Vectra.Detection.Tags | String | Detection tags | 
| Vectra.Detection.ThreatScore | Number | Detection threat score | 
| Vectra.Detection.TriageRuleID | String | Triage rule ID related to this detection | 
| Vectra.Detection.Type | String | Detection type \(Brute Force, Port Sweep, ...\) | 
| Vectra.Detection.URL | String | Detection URL to pivot to Vectra UI | 

### vectra-detection-get-pcap
***
Returns a Detection's PCAP file (if available)


#### Base Command

`vectra-detection-get-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The Detection ID you want to get the PCAP file from. | Optional | 


#### Context Output

There is no context output for this command.
### vectra-detection-markasfixed
***
Marks/Unmarks a Detection as fixed by providing the Detection ID


#### Base Command

`vectra-detection-markasfixed`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Detection ID you want to mark/unmark as fixed. | Optional | 
| fixed | The wanted detection status ("true", "false"). No default value. Possible values are: true, false. | Optional | 


#### Context Output

There is no context output for this command.
### vectra-detection-add-tags
***
Add tags to a Detection


#### Base Command

`vectra-detection-add-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Detection ID you want to add tags on. | Optional | 
| tags | The tags list (comma separated). | Optional | 


#### Context Output

There is no context output for this command.
### vectra-detection-del-tags
***
Delete tags from a Detection


#### Base Command

`vectra-detection-del-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Detection ID you want to del tags from. | Optional | 
| tags | The tags list (comma separated). | Optional | 


#### Context Output

There is no context output for this command.
### vectra-detection-tag-list

***
Returns a list of tags for a specified detection.

#### Base Command

`vectra-detection-tag-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Specify the ID of the detection. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.ID | Number | ID of the detection associated with the tags. | 
| Vectra.Detection.Tags | String | Tags associated to the detection. | 

#### Command example
```!vectra-detection-tag-list id="2" ```

#### Context Example
```json
{
    "Vectra.Detection": {
        "ID": 2,
        "Tags": [
            "note",
            "tag_from_xsoar",
            "tag_from_vectra"
        ]
    }
}
```

#### Human Readable Output

>##### List of tags: **note**, **tag_from_xsoar**, **tag_from_vectra**

### vectra-detection-note-add

***
Add a note to the detection.

#### Base Command

`vectra-detection-note-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required | 
| note | Note to be added in the specified detection_id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Notes.detection_id | Number | ID of the detection associated with the note. | 
| Vectra.Detection.Notes.note_id | Number | ID of the note. | 
| Vectra.Detection.Notes.date_created | Date | Date when the note was created. | 
| Vectra.Detection.Notes.date_modified | Date | Date when the note was last modified. | 
| Vectra.Detection.Notes.created_by | String | User who created the note. | 
| Vectra.Detection.Notes.modified_by | String | User who last modified the note. | 
| Vectra.Detection.Notes.note | String | Content of the note. | 

#### Command example
```!vectra-detection-note-add detection_id="7" note="test note" ```

#### Context Example
```json
{
    "Vectra.Detection.Notes": {
        "date_created": "2024-07-10T07:32:58.574942Z",
        "created_by": "xsoar",
        "note": "test note",
        "note_id": 1961,
        "detection_id": 7
    }
}
```

#### Human Readable Output

>##### The note has been successfully added to the detection.
>Returned Note ID: **1961**


### vectra-detection-note-update

***
Update a note in the detection.

#### Base Command

`vectra-detection-note-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required | 
| note_id | Specify the ID of the note.<br/><br/>Note: Use the vectra-detection-note-list command to get note_id. | Required | 
| note | Note to be updated for the specified note_id. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Notes.detection_id | Number | ID of the detection associated with the note. | 
| Vectra.Detection.Notes.note_id | Number | ID of the note. | 
| Vectra.Detection.Notes.date_created | Date | Date when the note was created. | 
| Vectra.Detection.Notes.date_modified | Date | Date when the note was last modified. | 
| Vectra.Detection.Notes.created_by | String | User who created the note. | 
| Vectra.Detection.Notes.modified_by | String | User who last modified the note. | 
| Vectra.Detection.Notes.note | String | Content of the note. | 

#### Command example
```!vectra-detection-note-update detection_id="9" note_id="1961" note="updated test note"```

#### Context Example
```json
{
    "Vectra.Detection.Notes": {
        "date_created": "2024-07-10T07:32:58.574942Z",
        "date_modified": "2024-07-12T06:43:29.546835Z",
        "created_by": "xsoar",
        "modified_by": "xsoar",
        "note": "updated test note",
        "note_id": 1961,
        "detection_id": 9
    }
}
```

#### Human Readable Output

>##### The note has been successfully updated in the detection.


### vectra-detection-note-remove

***
Remove a note from the detection.

#### Base Command

`vectra-detection-note-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required | 
| note_id | Specify the ID of the note.<br/><br/>Note: Use the vectra-detection-note-list command to get note_id. | Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!vectra-detection-note-remove detection_id=97" note_id="1961"```

#### Human Readable Output

>##### The note has been successfully removed from the detection.



### vectra-detection-note-list

***
List all notes of the specific detection.

#### Base Command

`vectra-detection-note-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_id | Specify the ID of the detection. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Notes.detection_id | Number | ID of the detection associated with the note. | 
| Vectra.Detection.Notes.note_id | Number | ID of the note. | 
| Vectra.Detection.Notes.date_created | Date | Date when the note was created. | 
| Vectra.Detection.Notes.date_modified | Date | Date when the note was last modified. | 
| Vectra.Detection.Notes.created_by | String | User who created the note. | 
| Vectra.Detection.Notes.modified_by | String | User who last modified the note. | 
| Vectra.Detection.Notes.note | String | Content of the note. | 

#### Command example
```!vectra-detection-note-list detection_id="9"```

#### Context Example
```json
{
    "Vectra.Detection.Notes": [
        {
            "date_created": "2024-07-12T04:52:20Z",
            "date_modified": "2024-07-12T10:21:03Z",
            "created_by": "xsoar",
            "modified_by": "xsoar",
            "note": "updated note 2nd",
            "note_id": 1961,
            "detection_id": 9
        },
        {
            "date_created": "2024-07-11T07:32:20Z",
            "created_by": "xsoar",
            "note": "your first test note",
            "note_id": 1937,
            "detection_id": 9
        }
    ]
}
```
#### Human Readable Output

>##### Notes Table
>|Note ID|Note|Created By|Created Date|Modified By|Modified Date|
>|---|---|---|---|---|---|
>| 1961 | updated note 2nd | xsoar | 2024-07-12T04:52:20Z | xsoar | 2024-07-12T10:21:03Z |
>| 1937 | your first test note | xsoar | 2024-07-11T07:32:20Z |  |  |

### vectra-outcome-describe
***
Returns a single outcome details


#### Base Command

`vectra-outcome-describe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Outcome ID you want to get details on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Outcome.IsBuiltIn | String | Is this Outcome a builtin Outcome | 
| Vectra.Outcome.Category | String | Outcome's category \('False Positive', 'Benign True Positive', 'Malicious True Positive'\) | 
| Vectra.Outcome.ID | Number | Outcome ID \(unique\) | 
| Vectra.Outcome.Title | String | Outcome title | 

### vectra-outcome-create
***
Creates a new assignment outcome


#### Base Command

`vectra-outcome-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | Outcome title (will be visible in the UI). | Optional | 
| category | Outcome category (one of the 3). Possible values are: Benign True Positive, Malicious True Positive, False Positive. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Outcome.IsBuiltIn | String | Is this Outcome a builtin Outcome | 
| Vectra.Outcome.Category | String | Outcome's category \('False Positive', 'Benign True Positive', 'Malicious True Positive'\) | 
| Vectra.Outcome.ID | Number | Outcome ID \(unique\) | 
| Vectra.Outcome.Title | String | Outcome title | 

### vectra-assignment-describe
***
Returns a single assignment details


#### Base Command

`vectra-assignment-describe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Assignment ID you want to get details on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Assignment.AccountID | Number | Account ID this assignment is linked to | 
| Vectra.Assignment.AssignedBy | String | Who lastly assigned this assignment | 
| Vectra.Assignment.AssignedDate | String | When this assignment was lastly assigned | 
| Vectra.Assignment.AssignedTo | String | To who this assignment is assigned | 
| Vectra.Assignment.HostID | String | Host ID this assignment is linked to | 
| Vectra.Assignment.ID | Number | Assignment ID \(unique\) | 
| Vectra.Assignment.IsResolved | Boolean | Is this assignment resolved | 
| Vectra.Assignment.OutcomeCategory | String | Assignment Outcome category | 
| Vectra.Assignment.OutcomeTitle | String | Assignment Outcome title | 
| Vectra.Assignment.TriagedDetections | String | List of Detection that have been triaged with the resolution | 
| Vectra.Assignment.TriagedAs | String | Name of the triage rule if any | 
| Vectra.Assignment.ResolvedBy | String | Who resolved this assignment | 
| Vectra.Assignment.ResolvedDate | string | When this assignment was resolved | 

### vectra-assignment-assign
***
Assigns an Account/Host entity to a Vectra User for investigation. If an assignment already exists on this entity, it will be reassigned


#### Base Command

`vectra-assignment-assign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assignee_id | Assignee's ID (Vectra User ID). | Optional | 
| assignment_id | Assignment ID if an assignment already exists for the given entity. | Optional | 
| account_id | Account ID. | Optional | 
| host_id | Host ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Assignment.AccountID | Number | Account ID this assignment is linked to | 
| Vectra.Assignment.AssignedBy | String | Who lastly assigned this assignment | 
| Vectra.Assignment.AssignedDate | String | When this assignment was lastly assigned | 
| Vectra.Assignment.AssignedTo | String | To who this assignment is assigned | 
| Vectra.Assignment.HostID | String | Host ID this assignment is linked to | 
| Vectra.Assignment.ID | Number | Assignment ID \(unique\) | 
| Vectra.Assignment.IsResolved | Boolean | Is this assignment resolved | 
| Vectra.Assignment.OutcomeCategory | String | Assignment Outcome category | 
| Vectra.Assignment.OutcomeTitle | String | Assignment Outcome title | 
| Vectra.Assignment.TriagedDetections | String | List of Detection that have been triaged with the resolution | 
| Vectra.Assignment.TriagedAs | String | Name of the triage rule if any | 
| Vectra.Assignment.ResolvedBy | String | Who resolved this assignment | 
| Vectra.Assignment.ResolvedDate | string | When this assignment was resolved | 

### vectra-assignment-resolve
***
Resolves an assignment by selecting resolution scheme. Could be 'resolving only' or 'resolving by filtering detections'


#### Base Command

`vectra-assignment-resolve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assignment_id | Assignment's ID. | Optional | 
| outcome_id | Assignment Outcome's ID. | Optional | 
| note | A note to add to this resolution. | Optional | 
| detections_filter | Do you want to filter detections when resolving this assignment ? [Default is None]. Possible values are: None, Filter Rule. | Optional | 
| filter_rule_name | Filter rule's name (when using filter_detections="Filter Rule"). | Optional | 
| detections_list | Detection IDs list you want to filter. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Assignment.AccountID | Number | Account ID this assignment is linked to | 
| Vectra.Assignment.AssignedBy | String | Who lastly assigned this assignment | 
| Vectra.Assignment.AssignedDate | String | When this assignment was lastly assigned | 
| Vectra.Assignment.AssignedTo | String | To who this assignment is assigned | 
| Vectra.Assignment.HostID | String | Host ID this assignment is linked to | 
| Vectra.Assignment.ID | Number | Assignment ID \(unique\) | 
| Vectra.Assignment.IsResolved | Boolean | Is this assignment resolved | 
| Vectra.Assignment.OutcomeCategory | String | Assignment Outcome category | 
| Vectra.Assignment.OutcomeTitle | String | Assignment Outcome title | 
| Vectra.Assignment.TriagedDetections | String | List of Detection that have been triaged with the resolution | 
| Vectra.Assignment.TriagedAs | String | Name of the triage rule if any | 
| Vectra.Assignment.ResolvedBy | String | Who resolved this assignment | 
| Vectra.Assignment.ResolvedDate | string | When this assignment was resolved | 

### vectra-user-describe
***
Returns a single Vectra User details


#### Base Command

`vectra-user-describe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | User ID you want to get details on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.User.Email | String | User's email address | 
| Vectra.User.ID | Number | User ID \(unique\) | 
| Vectra.User.Role | String | User's role | 
| Vectra.User.Type | String | User type \('Local', 'SAML', ...\) | 
| Vectra.User.Username | String | Username | 
| Vectra.User.LastLoginDate | String | User's last login datetime | 

### vectra-group-list

***
Returns a list of all groups.

#### Base Command

`vectra-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_type | Filter by group type. Possible values are: account, host, ip, domain. | Optional | 
| account_names | Filter by Account Names. Supports comma-separated values.<br/><br/>Note: Only valid when the group_type parameter is set to "account". | Optional | 
| domains | Filter by Domains. Supports comma-separated values.<br/><br/>Note: Only valid when the group_type parameter is set to "domain". | Optional | 
| host_ids | Filter by Host IDs. Supports comma-separated values.<br/><br/>Note: Only valid when the group_type parameter is set to "host". | Optional | 
| host_names | Filter by Host Names. Supports comma-separated values.<br/><br/>Note: Only valid when the group_type parameter is set to "host". | Optional | 
| importance | Filter by group importance. Possible values are: high, medium, low, never_prioritize. | Optional | 
| ips | Filter by IPs. Supports comma-separated values.<br/><br/>Note: Only valid when the group_type parameter is set to "ip". | Optional | 
| description | Filter by group description. | Optional | 
| last_modified_timestamp | Return only the groups which have a last modification timestamp equal to or after the given timestamp.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2023, 01 Mar 2023 04:45:33, 2023-04-17T14:05:44Z. | Optional | 
| last_modified_by | Filters by the user id who made the most recent modification to the group. | Optional | 
| group_name | Filters by group name. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Group.group_id | Number | ID of the group. | 
| Vectra.Group.name | String | Name of the group. | 
| Vectra.Group.description | String | Description of the group. | 
| Vectra.Group.last_modified | Date | Date when the group was last modified. | 
| Vectra.Group.last_modified_by | String | Name of the user who last modified the group. | 
| Vectra.Group.type | String | Type of the group. | 
| Vectra.Group.members.id | Number | Entity ID of member. | 
| Vectra.Group.members.name | String | Entity name of member. | 
| Vectra.Group.members.is_key_asset | Boolean | Indicates key asset. | 
| Vectra.Group.members.url | String | Entity URL of member. | 
| Vectra.Group.members.uid | String | Entity UID of member. | 
| Vectra.Group.rules.triage_category | String | Triage category of rule. | 
| Vectra.Group.rules.id | Number | ID of the rule. | 
| Vectra.Group.rules.description | String | Description of the rule. | 
| Vectra.Group.importance | String | Importance level of the group. | 
| Vectra.Group.cognito_managed | Boolean | Whether the group is managed by Cognito or not. | 

#### Command example
```!vectra-group-list group_type=account importance=high```
#### Context Example
```json
{
    "Vectra": {
        "Group": [
            {
                "description": "",
                "group_id": 1,
                "id": 1,
                "last_modified": "2024-07-22T06:44:44Z",
                "last_modified_by": "cds_xsoar",
                "members": [
                    {
                        "uid": "user@lab.test.local"
                    },
                    {
                        "uid": "O365:serviceprincipal_00000000-0000-0000-0000-000000000001"
                    }
                ],
                "name": "AccountNoBlock",
                "type": "account"
            },
            {
                "description": "",
                "group_id": 2,
                "id": 2,
                "last_modified": "2024-07-22T06:44:40Z",
                "last_modified_by": "cds_xsoar",
                "members": [
                    {
                        "uid": "O365:serviceprincipal_00000000-0000-0000-0000-000000000001"
                    }
                ],
                "name": "AccountBlock",
                "type": "account"
            }
        ]
    }
}
```

#### Human Readable Output

>### Groups Table
>|Group ID|Name|Group Type|Members|Last Modified Timestamp|
>|---|---|---|---|---|
>| 1 | AccountNoBlock | account | user@lab.test.local, O365:serviceprincipal_00000000-0000-0000-0000-000000000001 | 2024-07-22T06:44:44Z |
>| 2 | AccountBlock | account | O365:serviceprincipal_00000000-0000-0000-0000-000000000001 | 2024-07-22T06:44:40Z |


### vectra-group-assign

***
Assign members to the specified group.

#### Base Command

`vectra-group-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Specify Group ID to assign members.<br/><br/>Note: You can get the group_id by executing the \"vectra-group-list\" command. | Required | 
| members | A comma-separated list of member values based on the group type.<br/><br/>Note:<br/>You can get the members by executing the \"vectra-group-list\" command.<br/>If the group type is host, then the "Host IDs".<br/>If the group type is account, then "Account Names".<br/>If the group type is ip, then the list of "IPs".<br/>If the group type is domain, then the list of "Domains". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Group.group_id | Number | ID of the group. | 
| Vectra.Group.name | String | Name of the group. | 
| Vectra.Group.description | String | Description of the group. | 
| Vectra.Group.last_modified | Date | Date when the group was last modified. | 
| Vectra.Group.last_modified_by | String | Name of the user who last modified the group. | 
| Vectra.Group.type | String | Type of the group. | 
| Vectra.Group.members.id | Number | Entity ID of member. | 
| Vectra.Group.members.name | String | Entity name of member. | 
| Vectra.Group.members.is_key_asset | Boolean | Indicates key asset. | 
| Vectra.Group.members.url | String | Entity URL of member. | 
| Vectra.Group.members.uid | String | Entity UID of member. | 
| Vectra.Group.rules.triage_category | String | Triage category of rule. | 
| Vectra.Group.rules.id | Number | ID of the rule. | 
| Vectra.Group.rules.description | String | Description of the rule. | 

#### Command example
```!vectra-group-assign group_id=3557 members="account_4"```
#### Context Example
```json
{
    "Vectra": {
        "Group": {
        "id": 3,
        "name": "xsoar-account-group-2",
        "last_modified": "2023-09-04T09:22:46Z",
        "last_modified_by": "TEST Client",
        "members": [
            {
                "uid": "account_1"
            },
            {
                "uid": "account_2"
            },
            {
                "uid": "account_3"
            },
            {
                "uid": "account_4"
            }
        ],
        "type": "account",
        "group_id": 3
        }
    }
}
```

#### Human Readable Output

>### Member(s) account_4 have been assigned to the group.
>### Updated group details:
>|Group ID|Name|Group Type|Members|Last Modified Timestamp|
>|---|---|---|---|---|
>| 3 | xsoar-account-group-2 | account | account_1, account_2, account_3, account_4 | 2023-09-04T09:22:46Z |


### vectra-group-unassign

***
Unassign members from the specified group.

#### Base Command

`vectra-group-unassign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Specify Group ID to unassign members.<br/><br/>Note: You can get the group_id by executing the \"vectra-group-list\" command. | Required | 
| members | A comma-separated list of member values based on the group type.<br/><br/>Note:<br/>You can get the members by executing the \"vectra-group-list\" command.<br/>If the group type is host, then the "Host IDs".<br/>If the group type is account, then "Account Names".<br/>If the group type is ip, then the list of "IPs".<br/>If the group type is domain, then the list of "Domains". | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Group.group_id | Number | ID of the group. | 
| Vectra.Group.name | String | Name of the group. | 
| Vectra.Group.description | String | Description of the group. | 
| Vectra.Group.last_modified | Date | Date when the group was last modified. | 
| Vectra.Group.last_modified_by | String | Name of the user who last modified the group. | 
| Vectra.Group.type | String | Type of the group. | 
| Vectra.Group.members.id | Number | Entity ID of member. | 
| Vectra.Group.members.name | String | Entity name of member. | 
| Vectra.Group.members.is_key_asset | Boolean | Indicates key asset. | 
| Vectra.Group.members.url | String | Entity URL of member. | 
| Vectra.Group.members.uid | String | Entity UID of member. | 
| Vectra.Group.rules.triage_category | String | Triage category of rule. | 
| Vectra.Group.rules.id | Number | ID of the rule. | 
| Vectra.Group.rules.description | String | Description of the rule. | 

#### Command example
```!vectra-group-unassign group_id=5 members="2126"```
#### Context Example
```json
{
    "Vectra": {
        "Group": {
            "id": 2,
            "group_id": 2,
            "type": "host",
            "name": "TEST RENAME",
            "description": "TEST RENAME",
            "last_modified": "2023-09-04T06:27:57Z",
            "last_modified_by": "TEST Client"
        }
    }
}
```

#### Human Readable Output

>### Member(s) 2126 have been unassigned from the group.
>### Updated group details:
>|Group ID|Name|Group Type|Description|Last Modified Timestamp|
>|---|---|---|---|---|
>| 2 | TEST RENAME | host | TEST RENAME | 2023-09-04T06:27:57Z |

## Troubleshooting

### Receive Notification on an Incident Fetch Error

The administrator and Cortex XSOAR users on the recipient's list receive a notification when an integration experiences an incident fetch error. Cortex XSOAR users can select their notification method, such as email, from their user preferences. Refer to [Cortex XSOAR 6.13 documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Receive-Notification-on-an-Incident-Fetch-Error) or [Cortex XSOAR 8 Cloud documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Receive-notifications-on-an-incident-fetch-error) or [Cortex XSOAR 8.7 On-prem documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Receive-notifications-on-an-incident-fetch-error) for more information.

##### The following are tips for handling issues with mirroring incidents between Vectra and Cortex XSOAR

| **Issue** | **Recommendation** |
| --- | --- |
| Mirroring is not working. | Open Context Data and search for dbot. Confirm the dbot fields are configured correctly either through the mapper for that specific incident type or using setIncident. Specifically, make sure the integration instance is configured correctly for the mirroring direction (incoming, outgoing, both) - dbotMirrorId, dbotMirrorDirection, dbotMirrorInstance, dbotMirrorTags.|
| Required fields are not getting sent or not visible in UI. | This may be a mapping issue, specifically if you have used a custom mapper make sure you've covered all the out of box mapper fields. |
| Notes from Cortex XSOAR have not been mirrored in Vectra | Tag is required for mirroring notes from Cortex XSOAR to Vectra. There might be a reason the note is not tagged as the tag needs to be added manually in Cortex XSOAR.<br>Click **Actions** > **Tags** and add the "note" tag (OR the specific tag name which was set up in the Instance Configuration).|

### Docker timeout issue for Fetch Incidents

- If you encounter a timeout error while fetching incidents, you can try adjusting the value of the `max_fetch` parameter in the instance configuration. Setting it to a lower value, such as 50 can help prevent the timeout issue. 

- Another way to address this issue is to increase the timeout of the Docker container. By default, Docker containers have a timeout of 5 minutes. You can increase this timeout to a higher value, such as 10 minutes, to allow more time for the fetch command to complete. Refer to [this XSOAR documentation](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Integration-Server-Configurations) for more information.

### Handling HTTP 429 and 5xx Errors

The commands and fetch incidents mechanism will do up to 3 internal retries with a gap of 15, 30, and 60 seconds (exponentially) between the retries.
