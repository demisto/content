IBM QRadar SIEM helps security teams accurately detect and prioritize threats across the enterprise, supports API versions 10.1 and above. Provides intelligent insights that enable teams to respond quickly to reduce the impact of incidents.
## Configure QRadar v3_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for QRadar v3_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | \(e.g., https://192.168.0.1\) | True |
    | Username |  | True |
    | Password |  | True |
    | QRadar API Version | API version of QRadar \(e.g., '12.0'\). Minimum API version is 10.1. | True |
    | Incident Type |  | False |
    | Fetch mode |  | True |
    | Maximum number of events per incident. | The maximal amount of events to pull per incident. | False |
    | Number of offenses to pull per API call (max 50) |  | False |
    | Query to fetch offenses | Define a query to determine which offenses to fetch. E.g., "severity &gt;= 4 AND id &gt; 5 AND status=OPEN". | False |
    | Incidents Enrichment | IPs enrichment transforms IDs of the IPs of the offense to IP values. Asset enrichment adds correlated assets to the fetched offenses. | True |
    | Event fields to return from the events query (WARNING: This parameter is correlated to the incoming mapper and changing the values may adversely affect mapping). | The parameter uses the AQL SELECT syntax. For more information, see: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.4/com.ibm.qradar.doc/c_aql_intro.html | False |
    | Mirroring Options | How mirroring from QRadar to Cortex XSOAR should be done, available from QRadar 7.3.3 Fix Pack 3. For further explanation on how to check your QRadar version, see the integration documentation at https://xsoar.pan.dev. | False |
    | Close Mirrored XSOAR Incident | When selected, closing the QRadar offense is mirrored in Cortex XSOAR. | False |
    | The number of incoming incidents to mirror each time | Maximum number of incoming incidents to mirror each time. | False |
    | Advanced Parameters | Comma-separated configuration for advanced parameter values. E.g., EVENTS_INTERVAL_SECS=20,FETCH_SLEEP=5 | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Long running instance |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### qradar-offenses-list

***
Gets offenses from QRadar.

#### Base Command

`qradar-offenses-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to retrieve its details. Specify offense_id to get details about a specific offense. | Optional | 
| enrichment | IPs enrichment transforms IDs of the IPs of the offense to IP values. Asset enrichment adds correlated assets to the fetched offenses. Possible values are: IPs, IPs And Assets, None. Default is None. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query to filter offenses, e.g., "severity &gt;= 4 AND id &gt; 5 AND status=OPEN". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,severity,status". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offenses-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Description | String | Description of the offense. | 
| QRadar.Offense.Rules.id | Number | The ID of the rule. | 
| QRadar.Offense.Rules.type | String | The type of the rule. | 
| QRadar.Offense.Rules.name | String | The name of the rule. | 
| QRadar.Offense.EventCount | Number | Number of events that are associated with the offense. | 
| QRadar.Offense.FlowCount | Number | Number of flows that are associated with the offense. | 
| QRadar.Offense.AssignedTo | String | The user to whom the offense is assigned. | 
| QRadar.Offense.Followup | Boolean | Whether the offense is marked for follow-up. | 
| QRadar.Offense.SourceAddress | Number | Source addresses \(IPs if IPs enrich have been requested, else IDs of the IPs\) that are associated with the offense. | 
| QRadar.Offense.Protected | Boolean | Whether the offense is protected. | 
| QRadar.Offense.ClosingUser | String | The user who closed the offense. | 
| QRadar.Offense.DestinationHostname | String | Destination networks that are associated with the offense. | 
| QRadar.Offense.CloseTime | Date | Time when the offense was closed. | 
| QRadar.Offense.RemoteDestinationCount | Number | Number of remote destinations that are associated with the offense. | 
| QRadar.Offense.StartTime | Date | Date of the earliest item that contributed to the offense. | 
| QRadar.Offense.Magnitude | Number | Magnitude of the offense. | 
| QRadar.Offense.LastUpdatedTime | String | Date of the most recent item that contributed to the offense. | 
| QRadar.Offense.Credibility | Number | Credibility of the offense. | 
| QRadar.Offense.ID | Number | ID of the offense. | 
| QRadar.Offense.Categories | String | Event categories that are associated with the offense. | 
| QRadar.Offense.Severity | Number | Severity of the offense. | 
| QRadar.Offense.ClosingReason | String | Reason the offense was closed. | 
| QRadar.Offense.OffenseType | String | Type of the offense. | 
| QRadar.Offense.Relevance | Number | Relevance of the offense. | 
| QRadar.Offense.OffenseSource | String | Source of the offense. | 
| QRadar.Offense.DestinationAddress | Number | Destination addresses \(IPs if IPs enrichment have been requested, else IDs of the IPs\) that are associated with the offense. | 
| QRadar.Offense.Status | String | Status of the offense. Possible values: "OPEN", "HIDDEN", "CLOSED". | 
| QRadar.Offense.LinkToOffense | String | Link to the URL containing information about the offense. | 
| QRadar.Offense.Assets | String | Assets correlated to the offense, if enrichment was requested. | 

### qradar-offense-update

***
Updates an offense.

#### Base Command

`qradar-offense-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The ID of the offense to update. | Required | 
| enrichment | IPs enrichment transforms IDs of the IPs of the offense to IP values. Asset enrichment adds correlated assets to the fetched offenses. Possible values are: IPs, IPs And Assets, None. Default is None. | Optional | 
| protected | Whether the offense should be protected. Possible values are: true, false. | Optional | 
| follow_up | Whether the offense should be marked for follow-up. Possible values are: true, false. | Optional | 
| status | The new status for the offense. When the status of an offense is set to CLOSED, a valid closing_reason_id must be provided. To hide an offense, use the HIDDEN status. To show a previously hidden offense, use the OPEN status. Possible values are: OPEN, HIDDEN, CLOSED. | Optional | 
| closing_reason_id | The ID of a closing reason. You must provide a valid closing_reason_id when you close an offense. For a full list of closing reason IDs, use the 'qradar-closing-reasons' command. | Optional | 
| closing_reason_name | The name of a closing reason. You must provide a valid closing_reason_name when you close an offense. The default closing_reasons are: (1) False-Positive, Tuned (2) Non-Issues (3) Policy Violation. | Optional | 
| assigned_to | User to assign the offense to. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,severity,status". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offenses-offense_id-POST.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Description | String | Description of the offense. | 
| QRadar.Offense.Rules.id | Number | The ID of the rule. | 
| QRadar.Offense.Rules.type | String | The type of the rule. | 
| QRadar.Offense.Rules.name | String | The name of the rule. | 
| QRadar.Offense.EventCount | Number | Number of events that are associated with the offense. | 
| QRadar.Offense.FlowCount | Number | Number of flows that are associated with the offense. | 
| QRadar.Offense.AssignedTo | String | The user to whom the offense is assigned. | 
| QRadar.Offense.Followup | Boolean | Whether the offense is marked for follow-up. | 
| QRadar.Offense.SourceAddress | Number | Source addresses \(IPs if IPs enrich have been requested, else IDs of the IPs\) that are associated with the offense. | 
| QRadar.Offense.Protected | Boolean | Whether the offense is protected. | 
| QRadar.Offense.ClosingUser | String | The user who closed the offense. | 
| QRadar.Offense.DestinationHostname | String | Destination networks that are associated with the offense. | 
| QRadar.Offense.CloseTime | Date | Time when the offense was closed. | 
| QRadar.Offense.RemoteDestinationCount | Number | Number of remote destinations that are associated with the offense. | 
| QRadar.Offense.StartTime | Date | Date of the earliest item that contributed to the offense. | 
| QRadar.Offense.Magnitude | Number | Magnitude of the offense. | 
| QRadar.Offense.LastUpdatedTime | String | Date of the most recent item that contributed to the offense. | 
| QRadar.Offense.Credibility | Number | Credibility of the offense. | 
| QRadar.Offense.ID | Number | ID of the offense. | 
| QRadar.Offense.Categories | String | Event categories that are associated with the offense. | 
| QRadar.Offense.Severity | Number | Severity of the offense. | 
| QRadar.Offense.ClosingReason | String | Reason the offense was closed. | 
| QRadar.Offense.OffenseType | String | Type of the offense. | 
| QRadar.Offense.Relevance | Number | Relevance of the offense. | 
| QRadar.Offense.OffenseSource | String | Source of the offense. | 
| QRadar.Offense.DestinationAddress | Number | Destination addresses \(IPs if IPs enrichment have been requested, else IDs of the IPs\) that are associated with the offense. | 
| QRadar.Offense.Status | String | Status of the offense. Possible values: "OPEN", "HIDDEN", "CLOSED". | 
| QRadar.Offense.LinkToOffense | String | Link to the URL containing information about the offense. | 
| QRadar.Offense.Assets | String | Assets correlated to the offense, if enrichment was requested. | 

### qradar-closing-reasons

***
Retrieves a list of offense closing reasons.

#### Base Command

`qradar-closing-reasons`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| closing_reason_id | The closing reason ID for which to retrieve its details. Specify closing_reason_id to get details about a specific closing reason. | Optional | 
| include_reserved | If true, reserved closing reasons are included in the response. Possible values are: true, false. Default is false. | Optional | 
| include_deleted | If true, deleted closing reasons are included in the response. Possible values are: true, false. Default is false. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query to filter closing reasons, e.g. "id &gt; 5". For reference see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,text". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offense_closing_reasons-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.ClosingReasons.IsDeleted | Boolean | Whether the closing reason is deleted. Deleted closing reasons cannot be used to close an offense. | 
| QRadar.Offense.ClosingReasons.IsReserved | Boolean | Whether the closing reason is reserved. Reserved closing reasons cannot be used to close an offense. | 
| QRadar.Offense.ClosingReasons.Name | String | Name of the closing reason. | 
| QRadar.Offense.ClosingReasons.ID | Number | ID of the closing reason. | 

### qradar-offense-notes-list

***
Creates a note on an offense.

#### Base Command

`qradar-offense-notes-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to retrieve the notes for. | Required | 
| note_id | The note ID for which to retrieve its details. Specify note_id to get details about a specific note. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query to filter offense notes, e.g., "username=admin". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "username,note_text". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offenses-offense_id-notes-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.Text | String | The text of the note. | 
| QRadar.Note.CreateTime | Date | Creation date of the note. | 
| QRadar.Note.ID | Number | ID of the note. | 
| QRadar.Note.CreatedBy | String | The user who created the note. | 

### qradar-offense-note-create

***
Retrieves a list of notes for an offense.

#### Base Command

`qradar-offense-note-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to add the note to. | Required | 
| note_text | The text of the note. | Required | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "username,note_text". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offenses-offense_id-notes-POST.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.Text | String | The text of the note. | 
| QRadar.Note.CreateTime | Date | Creation date of the note. | 
| QRadar.Note.ID | Number | ID of the note. | 
| QRadar.Note.CreatedBy | String | The user who created the note. | 

### qradar-rules-list

***
Retrieves a list of rules.

#### Base Command

`qradar-rules-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The rule ID for which to retrieve its details. Specify rule_id to get details about a specific rule. | Optional | 
| rule_type | Retrieves rules corresponding to the specified rule type. Possible values are: EVENT, FLOW, COMMON, USER. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter rules, e.g., "type=EVENT". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "owner,identifier,origin". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi150.doc/15.0--analytics-rules-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Rule.Owner | String | Owner of the rule. | 
| QRadar.Rule.BaseHostID | Number | ID of the host from which the rule's base capacity was determined. | 
| QRadar.Rule.CapacityTimestamp | Number | Date when the rule's capacity values were last updated. | 
| QRadar.Rule.Origin | String | Origin of the rule. Possible values: "SYSTEM", "OVERRIDE", "USER". | 
| QRadar.Rule.CreationDate | Date | Date when rule was created. | 
| QRadar.Rule.Type | String | Type of the rule. Possible values: "EVENT", "FLOW", "COMMON", "USER". | 
| QRadar.Rule.Enabled | Boolean | Whether rule is enabled. | 
| QRadar.Rule.ModificationDate | Date | Date when the rule was last modified. | 
| QRadar.Rule.Name | String | Name of the rule. | 
| QRadar.Rule.AverageCapacity | Number | Moving average capacity in EPS of the rule across all hosts. | 
| QRadar.Rule.ID | Number | ID of the rule. | 
| QRadar.Rule.BaseCapacity | Number | Base capacity of the rule in events per second. | 

### qradar-rule-groups-list

***
Retrieves a list of the rule groups.

#### Base Command

`qradar-rule-groups-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_group_id | The rule group ID for which to retrieve its details. Specify rule_group_id to get details about a specific rule group. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter rules, e.g., "id &gt;= 125". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "owner,parent_id". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--analytics-rule_groups-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.RuleGroup.Owner | String | Owner of the group. | 
| QRadar.RuleGroup.ModifiedTime | Date | Date since the group was last modified. | 
| QRadar.RuleGroup.Level | Number | Depth of the group in the group hierarchy. | 
| QRadar.RuleGroup.Name | String | Name of the group. | 
| QRadar.RuleGroup.Description | String | Description of the group. | 
| QRadar.RuleGroup.ID | Number | ID of the group. | 
| QRadar.RuleGroup.ChildItems | String | Child items of the group. | 
| QRadar.RuleGroup.ChildGroups | Number | Child group IDs. | 
| QRadar.RuleGroup.Type | String | The type of the group. | 
| QRadar.RuleGroup.ParentID | Number | ID of the parent group. | 

### qradar-assets-list

***
Retrieves assets list.

#### Base Command

`qradar-assets-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The asset ID for which to retrieve its details. Specify asset_id to get details about a specific asset. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter assets, e.g., "domain_id=0". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,interfaces,users,properties". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--asset_model-assets-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Domain | String | DNS name. | 
| Endpoint.OS | String | Asset operating system. | 
| Endpoint.MACAddress | String | Asset MAC address. | 
| Endpoint.IPAddress | Unknown | IP addresses of the endpoint. | 
| QRadar.Asset.Interfaces.id | Number | ID of the interface. | 
| QRadar.Asset.Interfaces.mac_address | String | MAC address of the interface. Null if unknown. | 
| QRadar.Asset.Interfaces.ip_addresses.id | Number | ID of the interface. | 
| QRadar.Asset.Interfaces.ip_addresses.network_id | Number | Network ID of the network the IP belongs to. | 
| QRadar.Asset.Interfaces.ip_addresses.value | String | The IP address. | 
| QRadar.Asset.Interfaces.ip_addresses.type | String | Type of IP address. Possible values: "IPV4", "IPV6". | 
| QRadar.Asset.Interfaces.ip_addresses.created | Date | Date when the IP address was created. | 
| QRadar.Asset.Interfaces.ip_addresses.first_seen_scanner | Date | Date when the IP address was first seen during a vulnerability scan. | 
| QRadar.Asset.Interfaces.ip_addresses.first_seen_profiler | Date | Date when the IP address was first seen in event or flow traffic. | 
| QRadar.Asset.Interfaces.ip_addresses.last_seen_scanner | Date | Date when the IP address was most recently seen during a vulnerability scan. | 
| QRadar.Asset.Interfaces.ip_addresses.last_seen_profiler | Date | Date when the IP address was most recently seen in event or flow traffic. | 
| QRadar.Asset.Products.id | Number | The ID of this software product instance in QRadar's asset model. | 
| QRadar.Asset.Products.product_variant_id | Number | The ID of this software product variant in QRadar's catalog of products. | 
| QRadar.Asset.Products.first_seen_scanner | Date | Date when the product was first seen during a vulnerability scan. | 
| QRadar.Asset.Products.first_seen_profiler | Date | Date when the product was first seen in event or flow traffic. | 
| QRadar.Asset.Products.last_seen_scanner | Date | Date when the product was most recently seen seen during a vulnerability scan. | 
| QRadar.Asset.Products.last_seen_profiler | Date | Date when the product was most recently seen in event or flow traffic. | 
| QRadar.Asset.VulnerabilityCount | Number | The total number of vulnerabilities associated with this asset. | 
| QRadar.Asset.RiskScoreSum | Number | The sum of the CVSS scores of the vulnerabilities on this asset. | 
| QRadar.Asset.Hostnames.last_seen_profiler | Date | Date when the host was most recently seen in event or flow traffic. | 
| QRadar.Asset.Hostnames.created | Date | Date when the host was created. | 
| QRadar.Asset.Hostnames.last_seen_scanner | Date | Date when the host was most recently seen during a vulnerability scan. | 
| QRadar.Asset.Hostnames.name | String | Name of the host. | 
| QRadar.Asset.Hostnames.first_seen_scanner | Date | Date when the host was first seen during a vulnerability scan. | 
| QRadar.Asset.Hostnames.id | Number | ID of the host. | 
| QRadar.Asset.Hostnames.type | String | Type of the host. Possible values: "DNS", "NETBIOS", "NETBIOSGROUP". | 
| QRadar.Asset.Hostnames.first_seen_profiler | Date | Date when the host was first seen in event or flow traffic. | 
| QRadar.Asset.ID | Number | ID of the asset. | 
| QRadar.Asset.Users.last_seen_profiler | Date | Date when the user was most recently seen in event or flow traffic. | 
| QRadar.Asset.Users.last_seen_scanner | Date | Date when the user was most recently seen during a vulnerability scan. | 
| QRadar.Asset.Users.first_seen_scanner | Date | Date when the user was first seen during a vulnerability scan. | 
| QRadar.Asset.Users.id | Number | ID of the user. | 
| QRadar.Asset.Users.first_seen_profiler | Date | Date when the user was first seen in event or flow traffic. | 
| QRadar.Asset.Users.username | String | Name of the user. | 
| QRadar.Asset.DomainID | Number | ID of the domain this asset belongs to. | 
| QRadar.Asset.Properties.last_reported | Date | Date when the property was last updated. | 
| QRadar.Asset.Properties.name | String | Name of the property. | 
| QRadar.Asset.Properties.type_id | Number | Type ID of the property. | 
| QRadar.Asset.Properties.id | Number | ID of the property. | 
| QRadar.Asset.Properties.last_reported_by | String | The source of the most recent update to this property. | 
| QRadar.Asset.Properties.value | String | Property value. | 

### qradar-saved-searches-list

***
Retrieves a list of Ariel saved searches.

#### Base Command

`qradar-saved-searches-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| saved_search_id | The saved search ID for which to retrieve its details. Specify saved_search_id to get details about a specific saved search. | Optional | 
| timeout | Number of seconds until timeout for the specified command. Default is 35. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter saved searches, e.g., "database=EVENTS and is_dashboard=true". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,owner,description". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--ariel-saved_searches-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.SavedSearch.Owner | String | Owner of the saved search. | 
| QRadar.SavedSearch.Description | String | Description of the saved search. | 
| QRadar.SavedSearch.CreationDate | Date | Date when saved search was created. | 
| QRadar.SavedSearch.UID | String | UID of the saved search. | 
| QRadar.SavedSearch.Database | String | The database of the Ariel saved search, events, or flows. | 
| QRadar.SavedSearch.QuickSearch | Boolean | Whether the saved search is a quick search. | 
| QRadar.SavedSearch.Name | String | Name of the saved search. | 
| QRadar.SavedSearch.ModifiedDate | Date | Date when the saved search was most recently modified. | 
| QRadar.SavedSearch.ID | Number | ID of the saved search. | 
| QRadar.SavedSearch.AQL | String | The AQL query. | 
| QRadar.SavedSearch.IsShared | Boolean | Whether the saved search is shared with other users. | 

### qradar-searches-list

***
Retrieves the list of Ariel searches IDs. Search status and results can be polled by sending the search ID to the 'qradar-search-status-get' and 'qradar-search-results-get' commands.

#### Base Command

`qradar-searches-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.SearchID.SearchID | String | ID of the search. | 

### qradar-search-create

***
Creates a new asynchronous Ariel search. Returns the search ID. Search status and results can be polled by sending the search ID to the 'qradar-search-status-get' and 'qradar-search-results-get' commands. Accepts SELECT query expressions only.

#### Base Command

`qradar-search-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_expression | The AQL query to execute. Mutually exclusive with saved_search_id. | Optional | 
| saved_search_id | Saved search ID to execute. Mutually exclusive with query_expression. Saved search ID is the 'id' field returned by the 'qradar-saved-searches-list' command. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.Status | String | Status of the newly created search. | 
| QRadar.Search.ID | String | ID of the newly created search. | 

### qradar-search-status-get

***
Retrieves status information for a search, based on the search ID.

#### Base Command

`qradar-search-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The identifier for an Ariel search. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.Status | String | Status of the search. | 
| QRadar.Search.ID | String | ID of the search. | 

### qradar-search-results-get

***
Retrieves search results.

#### Base Command

`qradar-search-results-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The identifier for an Ariel search. | Required | 
| output_path | Replaces the default context output path for the query result (QRadar.Search.Result). E.g., for output_path=QRadar.Correlations, the result will be under the 'QRadar.Correlations' key in the context data. | Optional | 
| range | Range of events to return. (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.Result | Unknown | The result of the search. | 

### qradar-reference-sets-list

***
Retrieves a list of reference sets.

#### Base Command

`qradar-reference-sets-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The reference name of the reference set for which to retrieve its details. Specify ref_name to get details about a specific reference set. | Optional | 
| date_value | If set to true will try to convert the data values to ISO-8601 string. Possible values are: True, False. Default is False. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter reference sets, e.g., "timeout_type=FIRST_SEEN". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--reference_data-sets-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.TimeoutType | String | Timeout type of the reference set. Possible values: "UNKNOWN", "FIRST_SEEN", "LAST_SEEN". | 
| QRadar.Reference.NumberOfElements | Number | Number of elements in the reference set. | 
| QRadar.Reference.TimeToLive | String | Time left to live for the reference. | 
| QRadar.Reference.Data.LastSeen | Date | Date when this data was last seen. | 
| QRadar.Reference.Data.FirstSeen | Date | Date when this data was first seen. | 
| QRadar.Reference.Data.Source | String | Source of this data. | 
| QRadar.Reference.Data.Value | String | Data value. | 
| QRadar.Reference.CreationTime | Date | Date when the reference set was created. | 
| QRadar.Reference.Name | String | Name of the reference set. | 
| QRadar.Reference.ElementType | String | Type of the elements in the reference set. | 

### qradar-reference-set-create

***
Creates a new reference set.

#### Base Command

`qradar-reference-set-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to be created. | Required | 
| element_type | The element type for the values allowed in the reference set. Possible values are: ALN, ALNIC, NUM, IP, PORT, DATE. | Required | 
| timeout_type | Indicates if the time_to_live interval is based on when the data was first seen or last seen. Possible values are: FIRST_SEEN, LAST_SEEN, UNKNOWN. Default is UNKNOWN. | Optional | 
| time_to_live | The time to live interval, time range. for example: '1 month' or '5 minutes'. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--reference_data-sets-POST.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.TimeoutType | String | Timeout type of the reference set. Possible values: "UNKNOWN", "FIRST_SEEN", "LAST_SEEN". | 
| QRadar.Reference.NumberOfElements | Number | Number of elements in the reference set. | 
| QRadar.Reference.TimeToLive | String | Time left to live for the reference. | 
| QRadar.Reference.Data.LastSeen | Date | Date when this data was last seen. | 
| QRadar.Reference.Data.FirstSeen | Date | Date when this data was first seen. | 
| QRadar.Reference.Data.Source | String | Source of this data. | 
| QRadar.Reference.Data.Value | String | Data value. | 
| QRadar.Reference.CreationTime | Date | Date when the reference set was created. | 
| QRadar.Reference.Name | String | Name of the reference set. | 
| QRadar.Reference.ElementType | String | Type of the elements in the reference set. | 

### qradar-reference-set-delete

***
Removes a reference set or purges its contents.

#### Base Command

`qradar-reference-set-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to be deleted. Reference names can be found by 'Name' field in 'qradar-reference-sets-list' command. | Required | 
| purge_only | Indicates if the reference set should have its contents purged (true), keeping the reference set structure. If the value is 'false', or not specified the reference set is removed completely. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

There is no context output for this command.
### qradar-reference-set-value-upsert

***
Adds or updates an element in a reference set.

#### Base Command

`qradar-reference-set-value-upsert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to add or update an element in. Reference names can be found by the 'Name' field in the 'qradar-reference-sets-list' command. | Required | 
| value | Comma-separated list of the values to add or update in the reference set. If the values are dates, the supported date formats are: epoch, ISO, and time range (&lt;number&gt; &lt;time unit&gt;', e.g., 12 hours, 7 days.). | Required | 
| source | An indication of where the data originated. Default is reference data api. | Optional | 
| date_value | True if the specified value  type was date. Possible values are: true, false. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--reference_data-sets-name-POST.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.TimeoutType | String | Timeout type of the reference set. Possible values: "UNKNOWN", "FIRST_SEEN", "LAST_SEEN". | 
| QRadar.Reference.NumberOfElements | Number | Number of elements in the reference set. | 
| QRadar.Reference.TimeToLive | String | Time left to live for the reference. | 
| QRadar.Reference.Data.LastSeen | Date | Date when this data was last seen. | 
| QRadar.Reference.Data.FirstSeen | Date | Date when this data was first seen. | 
| QRadar.Reference.Data.Source | String | Source of this data. | 
| QRadar.Reference.Data.Value | String | Data value. | 
| QRadar.Reference.CreationTime | Date | Date when the reference set was created. | 
| QRadar.Reference.Name | String | Name of the reference set. | 
| QRadar.Reference.ElementType | String | Type of the elements in the reference set. | 

### qradar-reference-set-value-delete

***
Removes a value from a reference set.

#### Base Command

`qradar-reference-set-value-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set from which to remove a value. Reference names can be found by the 'Name' field in the 'qradar-reference-sets-list' command. | Required | 
| value | The value to remove from the reference set. If the specified value is date, the supported date formats are: epoch, ISO, and time range (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days.). | Required | 
| date_value | True if the specified value type was date. Possible values are: True, False. | Optional | 

#### Context Output

There is no context output for this command.
### qradar-domains-list

***
Gets the list of domains. You must have System Administrator or Security Administrator permissions to call this endpoint if you are trying to retrieve the details of all domains. You can retrieve details of domains that are assigned to your Security Profile without having the System Administrator or Security Administrator permissions. If you do not have the System Administrator or Security Administrator permissions, then for each domain assigned to your security profile you can only view the values for the ID and name fields. All other values return null.

#### Base Command

`qradar-domains-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The domain ID from which to retrieve its details. Specify domain_id to get details about a specific domain. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter domains, e.g., "id &gt; 3". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--config-domain_management-domains-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Domains.AssetScannerIDs | Number | Asset scanner IDs that are associated with the domain. | 
| QRadar.Domains.CustomProperties | Unknown | Custom properties of the domain. | 
| QRadar.Domains.Deleted | Boolean | Whether the domain has been deleted. | 
| QRadar.Domains.Description | String | Description of the domain. | 
| QRadar.Domains.EventCollectorIDs | Number | Event collector IDs that are assigned to this domain. | 
| QRadar.Domains.FlowCollectorIDs | Number | Flow collector IDs that are assigned to this domain. | 
| QRadar.Domains.FlowSourceIDs | Number | Flow source IDs that are assigned to this domain. | 
| QRadar.Domains.ID | Number | ID of the domain. | 
| QRadar.Domains.LogSourceGroupIDs | Number | Log source group IDs that are assigned to this domain. | 
| QRadar.Domains.LogSourceIDs | Number | Log source IDs that are assigned to this domain. | 
| QRadar.Domains.Name | String | Name of the domain. | 
| QRadar.Domains.QVMScannerIDs | Number | QVM scanner IDs that are assigned to this domain. | 
| QRadar.Domains.TenantID | Number | ID of the tenant that this domain belongs to. | 

### qradar-indicators-upload

***
Uploads indicators to QRadar.

#### Base Command

`qradar-indicators-upload`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of set to add or update data in. Reference names can be found by the 'Name' field in the 'qradar-reference-sets-list' command. | Required | 
| query | The query for getting indicators from Cortex XSOAR. | Optional | 
| limit | The maximum number of indicators to fetch from Cortex XSOAR. Default is 50. | Optional | 
| page | The page from which to get the indicators. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "name,timeout_type". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--reference_data-maps-bulk_load-name-POST.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.TimeoutType | String | Timeout type of the reference set. Possible values: "UNKNOWN", "FIRST_SEEN", "LAST_SEEN". | 
| QRadar.Reference.NumberOfElements | Number | Number of elements in the reference set. | 
| QRadar.Reference.TimeToLive | String | Time left to live for the reference. | 
| QRadar.Reference.Data.LastSeen | Date | Date when this data was last seen. | 
| QRadar.Reference.Data.FirstSeen | Date | Date when this data was first seen. | 
| QRadar.Reference.Data.Source | String | Source of this data. | 
| QRadar.Reference.Data.Value | String | Data value. | 
| QRadar.Reference.CreationTime | Date | Date when the reference set was created. | 
| QRadar.Reference.Name | String | Name of the reference set. | 
| QRadar.Reference.ElementType | String | Type of the elements in the reference set. | 

### qradar-geolocations-for-ip

***
Retrieves the MaxMind GeoIP data for the specified IP address.

#### Base Command

`qradar-geolocations-for-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Comma-separated list of IPs fro which to retrieve their geolocation. | Required | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "continent,ip_address". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--services-geolocations-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.GeoForIP.CityName | String | Name of the city that is associated with the IP address. | 
| QRadar.GeoForIP.ContinentName | String | Name of the continent that is associated with the IP address. | 
| QRadar.GeoForIP.LocationAccuracyRadius | Number | The approximate accuracy radius in kilometers around the latitude and longitude for the IP address. | 
| QRadar.GeoForIP.LocationAverageIncome | Number | The average income associated with the IP address. | 
| QRadar.GeoForIP.LocationLatitude | Number | The approximate latitude of the location associated with the IP address. | 
| QRadar.GeoForIP.LocationTimezone | String | Timezone of the location. | 
| QRadar.GeoForIP.LocationLongitude | Number | The approximate longitude of the location associated with the IP address. | 
| QRadar.GeoForIP.LocationMetroCode | Number | The metro code associated with the IP address. These are only available for IP addresses in the US. Returns the same metro codes as the Google AdWords API. | 
| QRadar.GeoForIP.LocationPopulationDensity | Number | The estimated number of people per square kilometer. | 
| QRadar.GeoForIP.PhysicalCountryIsoCode | String | ISO code of country where MaxMind believes the end user is located. | 
| QRadar.GeoForIP.PhysicalCountryName | String | Name of country where MaxMind believes the end user is located. | 
| QRadar.GeoForIP.RegisteredCountryIsoCode | String | ISO code of the country that the ISP has registered the IP address. | 
| QRadar.GeoForIP.RegisteredCountryName | String | Name of the country that the ISP has registered the IP address. | 
| QRadar.GeoForIP.RepresentedCountryIsoCode | String | ISO code of the country that is represented by users of the IP address. | 
| QRadar.GeoForIP.RepresentedCountryName | String | Name of the country that is represented by users of the IP address. | 
| QRadar.GeoForIP.RepresentedCountryConfidence | Number | Value between 0-100 that represents MaxMind's confidence that the represented country is correct. | 
| QRadar.GeoForIP.IPAddress | String | IP address to look up. | 
| QRadar.GeoForIP.Traits.autonomous_system_number | Number | The autonomous system number associated with the IP address. | 
| QRadar.GeoForIP.Traits.autonomous_system_organization | String | The organization associated with the registered autonomous system number for the IP address. | 
| QRadar.GeoForIP.Traits.domain | String | The second level domain associated with the IP address. | 
| QRadar.GeoForIP.Traits.internet_service_provider | String | The name of the internet service provider associated with the IP address. | 
| QRadar.GeoForIP.Traits.organization | String | The name of the organization associated with the IP address. | 
| QRadar.GeoForIP.Traits.user_type | String | The user type associated with the IP address. | 
| QRadar.GeoForIP.Coordinates | Number | Latitude and longitude by MaxMind. | 
| QRadar.GeoForIP.PostalCode | String | The postal code associated with the IP address. | 
| QRadar.GeoForIP.PostalCodeConfidence | Number | Value between 0-100 that represents MaxMind's confidence that the postal code is correct. | 

### qradar-log-sources-list

***
Retrieves a list of log sources.

#### Base Command

`qradar-log-sources-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qrd_encryption_algorithm | The algorithm to use for encrypting the sensitive data of this endpoint. Possible values are: AES128, AES256. Default is AES128. | Required | 
| qrd_encryption_password | The password to use for encrypting the sensitive data of this endpoint. If password was not given, random password will be generated. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter log sources, e.g., "auto_discovered=false". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,name,status". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see:  https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--config-event_sources-log_source_management-log_sources-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.LogSource.SendingIP | String | IP of the system which the log source is associated with, or fed by. | 
| QRadar.LogSource.Internal | Boolean | Whether log source is internal. | 
| QRadar.LogSource.ProtocolParameters | Unknown | Protocol parameters. | 
| QRadar.LogSource.Description | String | Description of the log source. | 
| QRadar.LogSource.Enabled | Boolean | Whether log source is enabled. | 
| QRadar.LogSource.GroupIDs | Number | Log source group IDs. | 
| QRadar.LogSource.Credibility | Number | Credibility of the log source. | 
| QRadar.LogSource.ID | Number | ID of the log source. | 
| QRadar.LogSource.ProtocolTypeID | Number | Protocol type used by log source. | 
| QRadar.LogSource.CreationDate | Date | Date when log source was created. | 
| QRadar.LogSource.Name | String | Name of the log source. | 
| QRadar.LogSource.AutoDiscovered | Boolean | Whether log source was auto discovered. | 
| QRadar.LogSource.ModifiedDate | Date | Date when log source was last modified. | 
| QRadar.LogSource.TypeID | Number | The log source type. | 
| QRadar.LogSource.LastEventTime | Date | Date when the last event was received by the log source. | 
| QRadar.LogSource.Gateway | Boolean | Whether log source is configured as a gateway. | 
| QRadar.LogSource.Status | Unknown | Status of the log source. | 

### qradar-get-custom-properties

***
Retrieves a list of event regex properties.

#### Base Command

`qradar-get-custom-properties`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field_name | A comma-separated list of names of the exact properties to search for. | Optional | 
| limit | The maximum number of regex event properties to fetch. Default is 25. | Optional | 
| like_name | A comma-separated list names of a properties to search for. Values are case insensitive. | Optional | 
| range | Range of results to return (e.g.: 0-20, 3-5, 3-3). Default is 0-49. | Optional | 
| filter | Query by which to filter regex properties, e.g., "auto_discovered=false". For reference, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | Comma-separated list of fields to retrieve in the response. Fields that are not explicitly named are excluded. E.g., "id,gateway". Specify subfields in brackets and multiple fields in the same object separated by commas. For a full list of available fields, see: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--config-event_sources-custom_properties-regex_properties-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Properties.identifier | String | ID of the event regex property. | 
| QRadar.Properties.modification_date | Date | Date when the event regex property was last updated. | 
| QRadar.Properties.datetime_format | String | Date/time pattern that the event regex property matches. | 
| QRadar.Properties.property_type | String | Property type. Possible values: "STRING", "NUMERIC", "IP", "PORT", "TIME". | 
| QRadar.Properties.name | String | Name of the event regex property. | 
| QRadar.Properties.auto_discovered | Boolean | Whether the event regex property was auto discovered. | 
| QRadar.Properties.description | String | Description of the event regex property. | 
| QRadar.Properties.id | Number | ID of the event regex property. | 
| QRadar.Properties.use_for_rule_engine | Boolean | Whether the event regex property is parsed when the event is received. | 
| QRadar.Properties.creation_date | Date | Date when the event regex property was created. | 
| QRadar.Properties.locale | String | Language tag of what locale the property matches. | 
| QRadar.Properties.username | String | The owner of the event regex property. | 

### qradar-reset-last-run

***
Resets the fetch incidents last run value, which resets the fetch to its initial fetch state. (Will try to fetch the first available offense).

#### Base Command

`qradar-reset-last-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### get-mapping-fields

***
Returns the list of fields for an incident type. This command should be used for debugging purposes.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### get-remote-data

***
Gets remote data from a remote incident. This method does not update the current incident, and should be used for debugging purposes.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The offense ID. | Required | 
| lastUpdate | Date string in local time representing the last time the incident was updated. The incident is only returned if it was modified after the last update time. | Required | 

#### Context Output

There is no context output for this command.
### get-modified-remote-data

***
Returns the list of incidents IDs that were modified since the last update time. Note that this method is for debugging purposes. The get-modified-remote-data command is used as part of the mirroring feature, which is available from version 6.1.

#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Date string in local time representing the last time the incident was updated. The incident is only returned if it was modified after the last update time. | Optional | 

#### Context Output

There is no context output for this command.
### qradar-offenses

***
Gets offenses from QRadar.

#### Base Command

`qradar-offenses`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Query by which to filter offenses. For reference, consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named, are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names. For reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-GET.html. | Optional | 
| range | Range of results to return. e.g.: 0-20. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Followup | boolean | Offense followup. | 
| QRadar.Offense.Credibility | number | The credibility of the offense. | 
| QRadar.Offense.Relevance | number | The relevance of the offense. | 
| QRadar.Offense.Severity | number | The severity of the offense. | 
| QRadar.Offense.SourceAddress | Unknown | The source addresses that are associated with the offense. | 
| QRadar.Offense.DestinationAddress | Unknown | The destination addresses that are associated with the offense. | 
| QRadar.Offense.AssignedTo | string | The user the offense is assigned to. | 
| QRadar.Offense.StartTime | date | The time \(ISO\) when the offense was started. | 
| QRadar.Offense.ID | int | The ID of the offense. | 
| QRadar.Offense.DestinationHostname | Unknown | Destintion hostname. | 
| QRadar.Offense.Description | string | The description of the offense. | 
| QRadar.Offense.EventCount | number | The number of events that are associated with the offense. | 
| QRadar.Offense.OffenseSource | string | The source of the offense. | 
| QRadar.Offense.Status | string | The status of the offense. One of "OPEN", "HIDDEN", or "CLOSED". | 
| QRadar.Offense.Magnitude | number | The magnitude of the offense. | 
| QRadar.Offense.ClosingUser | string | The user that closed the offense. | 
| QRadar.Offense.ClosingReason | string | The offense closing reason. | 
| QRadar.Offense.CloseTime | date | The time when the offense was closed. | 
| QRadar.Offense.LastUpdatedTime | date | The time \(ISO\) when the offense was last updated. | 
| QRadar.Offense.Categories | Unknown | Event categories that are associated with the offense. | 
| QRadar.Offense.FlowCount | number | The number of flows that are associated with the offense. | 
| QRadar.Offense.FollowUp | boolean | Offense followup. | 
| QRadar.Offense.OffenseType | string | A number that represents the offense type. | 
| QRadar.Offense.Protected | boolean | Is the offense protected. | 
| QRadar.Offense.RemoteDestinationCount | Unknown | The remote destinations that are associated with the offesne. If this value is greater than 0 that means your offense has a remote destination, you will need to use QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 

### qradar-offense-by-id

***
Gets offense with matching offense ID from qradar.

#### Base Command

`qradar-offense-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | Offense ID. | Required | 
| filter | Query to filter offense. For reference please consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-GET.html. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Followup | boolean | Offense followup. | 
| QRadar.Offense.Credibility | number | The credibility of the offense. | 
| QRadar.Offense.Relevance | number | The relevance of the offense. | 
| QRadar.Offense.Severity | number | The severity of the offense. | 
| QRadar.Offense.SourceAddress | Unknown | The source addresses that are associated with the offense. | 
| QRadar.Offense.DestinationAddress | Unknown | The local destination addresses that are associated with the offense. If your offense has a remote destination, you will need to use the QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 
| QRadar.Offense.RemoteDestinationCount | Unknown | The remote destination that are associated with the offesne. If this value is greater than 0, it means that your offense has a remote destination, you will need to use the QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 
| QRadar.Offense.AssignedTo | string | The user the offense is assigned to. | 
| QRadar.Offense.StartTime | date | The time \(ISO\) when the offense was started. | 
| QRadar.Offense.ID | int | The ID of the offense. | 
| QRadar.Offense.DestinationHostname | Unknown | Destintion hostname. | 
| QRadar.Offense.Description | string | The description of the offense. | 
| QRadar.Offense.EventCount | number | The number of events that are associated with the offense. | 
| QRadar.Offense.OffenseSource | string | The source of the offense. | 
| QRadar.Offense.Status | string | The status of the offense. One of "OPEN", "HIDDEN", or "CLOSED". | 
| QRadar.Offense.Magnitude | number | The magnitude of the offense. | 
| QRadar.Offense.ClosingUser | string | The user that closed the offense. | 
| QRadar.Offense.ClosingReason | string | The offense closing reason. | 
| QRadar.Offense.CloseTime | date | The time when the offense was closed. | 
| QRadar.Offense.LastUpdatedTime | date | The time \(ISO\) when the offense was last updated. | 
| QRadar.Offense.Categories | Unknown | Event categories that are associated with the offense. | 
| QRadar.Offense.FlowCount | number | The number of flows that are associated with the offense. | 
| QRadar.Offense.FollowUp | boolean | Offense followup. | 
| QRadar.Offense.OffenseType | string | A number that represents the offense type. | 
| QRadar.Offense.Protected | boolean | Is the offense protected. | 

### qradar-update-offense

***
Update an offense.

#### Base Command

`qradar-update-offense`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The ID of the offense to update. | Required | 
| protected | Set to true to protect the offense. Possible values are: true, false. | Optional | 
| follow_up | Set to true to set the follow up flag on the offense. Possible values are: true, false. | Optional | 
| status | The new status for the offense. Possible values are: OPEN, HIDDEN, CLOSED. | Optional | 
| closing_reason_id | The id of a closing reason. You must provide a valid closing_reason_name when you close an offense. The default closing_reasons are: (1) False-Positive, Tuned (2) Non-Issues (3) Policy Violation. | Optional | 
| closing_reason_name | The name of a closing reason. You must provide a valid closing_reason_name when you close an offense. The default closing_reasons are: (1) False-Positive, Tuned (2) Non-Issues (3) Policy Violation. | Optional | 
| assigned_to | A user to assign the offense to. | Optional | 
| fields | Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object  separated by commas. Please consult - https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-POST.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.Followup | boolean | Offense followup. | 
| QRadar.Offense.Credibility | number | The credibility of the offense. | 
| QRadar.Offense.Relevance | number | The relevance of the offense. | 
| QRadar.Offense.Severity | number | The severity of the offense. | 
| QRadar.Offense.SourceAddress | Unknown | The source addresses that are associated with the offense. | 
| QRadar.Offense.DestinationAddress | Unknown | The destination addresses that are associated with the offense. | 
| QRadar.Offense.AssignedTo | string | The user the offense is assigned to. | 
| QRadar.Offense.StartTime | date | The time \(ISO\) when the offense was started. | 
| QRadar.Offense.ID | int | The ID of the offense. | 
| QRadar.Offense.DestinationHostname | Unknown | Destintion hostname. | 
| QRadar.Offense.Description | string | The description of the offense. | 
| QRadar.Offense.EventCount | number | The number of events that are associated with the offense. | 
| QRadar.Offense.OffenseSource | string | The source of the offense. | 
| QRadar.Offense.Status | string | The status of the offense. One of "OPEN", "HIDDEN", or "CLOSED". | 
| QRadar.Offense.Magnitude | number | The magnitude of the offense. | 
| QRadar.Offense.ClosingUser | string | The user that closed the offense. | 
| QRadar.Offense.ClosingReason | string | The offense closing reason. | 
| QRadar.Offense.CloseTime | date | The time when the offense was closed. | 
| QRadar.Offense.LastUpdatedTime | date | The time \(ISO\) when the offense was last updated. | 
| QRadar.Offense.Categories | Unknown | Event categories that are associated with the offense. | 
| QRadar.Offense.FlowCount | number | The number of flows that are associated with the offense. | 
| QRadar.Offense.FollowUp | boolean | Offense followup. | 
| QRadar.Offense.OffenseType | string | A number that represents the offense type. | 
| QRadar.Offense.Protected | boolean | Is the offense protected. | 
| QRadar.Offense.RemoteDestinationCount | Unknown | The remote destinations that are associated with the offesne. If this value is greater than 0 that means your offense has a remote destination, you will need to use QRadarFullSearch playbook with the following query - SELECT destinationip FROM events WHERE inOffense\(&lt;offenseID&gt;\) GROUP BY destinationip | 

### qradar-searches

***
Searches in QRadar using AQL. It is highly recommended to use the playbook 'QRadarFullSearch' instead of this command - it will execute the search, and will return the result.

#### Base Command

`qradar-searches`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_expression | The query expressions in AQL (for more information about Ariel Query Language, review "https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.0/com.ibm.qradar.doc/c_aql_intro.html"). | Required | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.ID | number | Search ID. | 
| QRadar.Search.Status | string | The status of the search. | 

### qradar-get-search

***
Gets a specific search id and status.

#### Base Command

`qradar-get-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The search id. | Required | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.ID | number | Search ID. | 
| QRadar.Search.Status | string | The status of the search. | 

### qradar-get-search-results

***
Gets search results.

#### Base Command

`qradar-get-search-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search_id | The search id. | Required | 
| range | Range of results to return. e.g.: 0-20. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 
| output_path | Replaces the default context output path for the query result (QRadar.Search.Result). e.g. for output_path=QRadar.Correlations the result will be under the key "QRadar.Correlations" in the context data. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Search.Result | Unknown | The result of the search. | 

### qradar-get-assets

***
List all assets found in the model.

#### Base Command

`qradar-get-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | Query to filter assets. For reference please consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--asset_model-assets-GET.html. | Optional | 
| range | Range of results to return. e.g.: 0-20. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Asset.ID | number | The ID of the asset. | 
| Endpoint.IPAddress | Unknown | IP address of the asset. | 
| QRadar.Asset.Name.Value | string | Name of the asset. | 
| Endpoint.OS | number | Asset OS. | 
| QRadar.Asset.AggregatedCVSSScore.Value | number | CVSSScore. | 
| QRadar.Asset.AggregatedCVSSScore.LastUser | string | Last user who updated the Aggregated CVSS Score. | 
| QRadar.Asset.Weight.Value | number | Asset weight. | 
| QRadar.Asset.Weight.LastUser | string | Last user who updated the weight. | 
| QRadar.Asset.Name.LastUser | string | Last user who updated the name. | 

### qradar-get-asset-by-id

***
Retrieves the asset by id.

#### Base Command

`qradar-get-asset-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The ID of the requested asset. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Asset.ID | number | The ID of the asset. | 
| Endpoint.MACAddress | Unknown | Asset MAC address. | 
| Endpoint.IPAddress | Unknown | IP address of the endpoint. | 
| QRadar.Asset.ComplianceNotes.Value | string | Compliance notes. | 
| QRadar.Asset.CompliancePlan.Value | string | Compliance plan. | 
| QRadar.Asset.CollateralDamagePotential.Value | Unknown | Collateral damage potential. | 
| QRadar.Asset.AggregatedCVSSScore.Value | number | CVSSScore. | 
| QRadar.Asset.Name.Value | string | Name of the asset. | 
| QRadar.Asset.GroupName | string | Name of the asset's group. | 
| Endpoint.Domain | Unknown | DNS name. | 
| Endpoint.OS | Unknown | Asset OS. | 
| QRadar.Asset.Weight.Value | number | Asset weight. | 
| QRadar.Asset.Vulnerabilities.Value | Unknown | Vulnerabilities. | 
| QRadar.Asset.Location | string | Location. | 
| QRadar.Asset.Description | string | The asset description. | 
| QRadar.Asset.SwitchID | number | Switch ID. | 
| QRadar.Asset.SwitchPort | number | Switch port. | 
| QRadar.Asset.Name.LastUser | string | Last user who updated the name. | 
| QRadar.Asset.AggregatedCVSSScore.LastUser | string | Last user who updated the Aggregated CVSS Score. | 
| QRadar.Asset.Weight.LastUser | string | Last user who updated the weight. | 
| QRadar.Asset.ComplianceNotes.LastUser | string | Last user who updated the compliance notes. | 
| QRadar.Asset.CompliancePlan.LastUser | string | Last user who updated the compliance plan. | 
| QRadar.Asset.CollateralDamagePotential.LastUser | string | Last user who updated the collateral damage potential. | 
| QRadar.Asset.Vulnerabilities.LastUser | string | Last user who updated the vulnerabilities. | 

### qradar-get-closing-reasons

***
Get closing reasons.

#### Base Command

`qradar-get-closing-reasons`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| include_reserved | If true, reserved closing reasons are included in the response. Possible values are: true, false. Default is true. | Optional | 
| include_deleted | If true, deleted closing reasons are included in the response. Possible values are: true, false. Default is true. | Optional | 
| filter | Query to filter results. For reference, consult: https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.1/com.ibm.qradar.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names. For reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offense_closing_reasons-GET.html. | Optional | 
| range | Range of results to return. e.g.: 0-20. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Offense.ClosingReasons.ID | number | Closing reason ID. | 
| QRadar.Offense.ClosingReasons.Name | string | Closing reason name. | 

### qradar-get-note

***
Retrieve a note for an offense.

#### Base Command

`qradar-get-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to retrieve the note from. | Required | 
| note_id | The note ID. | Optional | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names. For reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-note_id-GET.html. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.ID | number | Note ID. | 
| QRadar.Note.Text | string | Note text. | 
| QRadar.Note.CreateTime | date | The creation time of the note. | 
| QRadar.Note.CreatedBy | string | The user who created the note. | 

### qradar-create-note

***
Create a note on an offense.

#### Base Command

`qradar-create-note`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offense_id | The offense ID to add the note to. | Required | 
| note_text | The note text. | Required | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names. For reference, consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-POST.html. | Optional | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Note.ID | number | Note ID. | 
| QRadar.Note.Text | string | Note text. | 
| QRadar.Note.CreateTime | date | The creation time of the note. | 
| QRadar.Note.CreatedBy | string | The user who created the note. | 

### qradar-get-reference-by-name

***
Information about the reference set that had data added or updated. This returns the information set, but not the contained data. This feature is supported from version 8.1 and upward.

#### Base Command

`qradar-get-reference-by-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the requestered reference. | Required | 
| headers | Table headers to use the human readable output (if none provided, will show all table headers). | Optional | 
| date_value | If set to true will try to convert the data values to ISO-8601 string. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeToLive | string | Reference time to live. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. Valid values are: UNKNOWN, FIRST_SEEN, LAST_SEEN | 
| QRadar.Reference.Data | Unknown | Reference set items. | 

### qradar-create-reference-set

***
Creates a new reference set. If the provided name is already in use, this command will fail.

#### Base Command

`qradar-create-reference-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | Reference name to be created. | Required | 
| element_type | The element type for the values allowed in the reference set. The allowed values are: ALN (alphanumeric), ALNIC (alphanumeric ignore case), IP (IP address), NUM (numeric), PORT (port number) or DATE. Note that date values need to be represented in milliseconds since the Unix Epoch January 1st 1970. Possible values are: ALN, ALNIC, IP, NUM, PORT, DATE. | Required | 
| timeout_type | The allowed values are "FIRST_SEEN", LAST_SEEN and UNKNOWN. The default value is UNKNOWN. Possible values are: FIRST_SEEN, LAST_SEEN, UNKNOWN. | Optional | 
| time_to_live | The time to live interval, for example: "1 month" or "5 minutes". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.CreationTime | date | Creation time of the reference set. | 
| QRadar.Reference.ElementType | string | The element type for the values allowed in the reference set. The allowed values are: ALN \(alphanumeric\), ALNIC \(alphanumeric ignore case\), IP \(IP address\), NUM \(numeric\), PORT \(port number\) or DATE. | 
| QRadar.Reference.Name | string | Name of the reference set. | 
| QRadar.Reference.NumberOfElements | number | Number of elements in the created reference set. | 
| QRadar.Reference.TimeoutType | string | Timeout type of the reference. The allowed values are FIRST_SEEN, LAST_SEEN and UNKNOWN. | 

### qradar-delete-reference-set

***
Deletes a reference set corresponding to the name provided.

#### Base Command

`qradar-delete-reference-set`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of reference set to delete. | Required | 

#### Context Output

There is no context output for this command.
### qradar-create-reference-set-value

***
Add or update a value in a reference set.

#### Base Command

`qradar-create-reference-set-value`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to add or update a value in. | Required | 
| value | The value/s to add or update in the reference set. Note: Date values must be represented in epoch in reference sets (milliseconds since the Unix Epoch January 1st 1970). If 'date_value' is set to 'True', then the argument will be converted from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. | Required | 
| source | An indication of where the data originated. The default value is 'reference data api'. | Optional | 
| date_value | If set to True, will convert 'value' argument from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN. | 

### qradar-update-reference-set-value

***
Adds or updates a value in a reference set.

#### Base Command

`qradar-update-reference-set-value`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to add or update a value in. | Required | 
| value | A comma-separated list of values to add or update in the reference set. Date values must be represented in milliseconds since the Unix Epoch January 1st 1970. | Required | 
| source | An indication of where the data originated. The default value is 'reference data api'. | Optional | 
| date_value | If set to True, will convert 'value' argument from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN | 

### qradar-delete-reference-set-value

***
Deletes a value in a reference set.

#### Base Command

`qradar-delete-reference-set-value`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to remove a value from. | Required | 
| value | The value to remove from the reference set. | Required | 
| date_value | If set to True will convert 'value' argument from date in format: '%Y-%m-%dT%H:%M:%S.%f000Z' (e.g. '2018-11-06T08:56:41.000000Z') to epoch. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Reference.Name | string | The name of the reference set. | 
| QRadar.Reference.CreationTime | date | The creation time \(ISO\) of the reference. | 
| QRadar.Reference.ElementType | string | Reference element type. | 
| QRadar.Reference.NumberOfElements | number | Number of elements. | 
| QRadar.Reference.TimeoutType | string | Reference timeout type. One of: UNKNOWN, FIRST_SEEN, LAST_SEEN | 

### qradar-get-domains

***
Retrieve all Domains.

#### Base Command

`qradar-get-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-note_id-GET.html. | Optional | 
| range | Number of results in return. | Optional | 
| filter | Query to filter offenses. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Domains.AssetScannerIDs | Number | Array of Asset Scanner IDs. | 
| QRadar.Domains.CustomProperties | String | Custom properties of the domain. | 
| QRadar.Domains.Deleted | Boolean | Indicates if the domain is deleted. | 
| QRadar.Domains.Description | String | Description of the domain. | 
| QRadar.Domains.EventCollectorIDs | Number | Array of Event Collector IDs. | 
| QRadar.Domains.FlowCollectorIDs | Number | Array of Flow Collector IDs. | 
| QRadar.Domains.FlowSourceIDs | Number | Array of Flow Source IDs. | 
| QRadar.Domains.ID | Number | ID of the domain. | 
| QRadar.Domains.LogSourceGroupIDs | Number | Array of Log Source Group IDs. | 
| QRadar.Domains.LogSourceIDs | Number | Array of Log Source IDs. | 
| QRadar.Domains.Name | String | Name of the Domain. | 
| QRadar.Domains.QVMScannerIDs | Number | Array of QVM Scanner IDs. | 
| QRadar.Domains.TenantID | Number | ID of the Domain tenant. | 

### qradar-get-domain-by-id

***
Retrieves Domain information By ID.

#### Base Command

`qradar-get-domain-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the domain. | Required | 
| fields | If used, will filter all fields except for the specified ones. Use this parameter to specify which fields you would like to get back in the response. Fields that are not explicitly named are excluded. Specify subfields in brackets and multiple fields in the same object are separated by commas. The filter uses QRadar's field names, for reference please consult: https://www.ibm.com/support/knowledgecenter/SSKMKU/com.ibm.qradar.doc_cloud/9.1--siem-offenses-offense_id-notes-note_id-GET.html. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.Domains.AssetScannerIDs | Number | Array of Asset Scanner IDs. | 
| QRadar.Domains.CustomProperties | String | Custom properties of the domain. | 
| QRadar.Domains.Deleted | Boolean | Indicates if the domain is deleted. | 
| QRadar.Domains.Description | String | Description of the domain. | 
| QRadar.Domains.EventCollectorIDs | Number | Array of Event Collector IDs. | 
| QRadar.Domains.FlowCollectorIDs | Number | Array of Flow Collector IDs. | 
| QRadar.Domains.FlowSourceIDs | Number | Array of Flow Source IDs. | 
| QRadar.Domains.ID | Number | ID of the domain. | 
| QRadar.Domains.LogSourceGroupIDs | Number | Array of Log Source Group IDs. | 
| QRadar.Domains.LogSourceIDs | Number | Array of Log Source IDs. | 
| QRadar.Domains.Name | String | Name of the Domain. | 
| QRadar.Domains.QVMScannerIDs | Number | Array of QVM Scanner IDs. | 
| QRadar.Domains.TenantID | Number | ID of the Domain tenant. | 

### qradar-upload-indicators

***
Uploads indicators from Demisto to Qradar.

#### Base Command

`qradar-upload-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ref_name | The name of the reference set to add or update a value in. To create a new reference set, you need to set the element type. | Required | 
| element_type | The element type for the values permitted in the reference set. Only required when creating a new reference set. The valid values are: ALN (alphanumeric), ALNIC (alphanumeric ignore case), IP (IP address), NUM (numeric), PORT (port number) or DATE. Note that date values need to be represented in milliseconds since the Unix Epoch January 1st 1970. Possible values are: ALN, ALNIC, IP, NUM, PORT, DATE. | Optional | 
| timeout_type | The timeout_type can be "FIRST_SEEN", "LAST_SEEN", or "UNKNOWN". The default value is UNKNOWN. Only required for creating a new reference set. Possible values are: FIRST_SEEN, LAST_SEEN, UNKNOWN. | Optional | 
| time_to_live | The time to live interval, for example: "1 month" or "5 minutes". Only required when creating a new reference set. | Optional | 
| query | The query for getting indicators. | Required | 
| limit | The maximum number of indicators to return. The default value is 1000. Default is 1000. | Optional | 
| page | The page from which to get the indicators. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### qradar-ips-source-get

***
Get Source IPs

#### Base Command

`qradar-ips-source-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_ip | Comma separated list. Source IPs to retrieve their data, E.g "192.168.0.1,192.160.0.2". | Optional | 
| filter | Query to filter IPs. E.g, filter=`source_ip="192.168.0.1"`. For reference please consult: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the ones specified. Use this argument to specify which fields should be returned in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://www.ibm.com/docs/en/qradar-common?topic=endpoints-get-siemsource-addresses. | Optional | 
| range | Range of results to return. e.g.: 0-20. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.SourceIP.ID | Number | The ID of the destination address. | 
| QRadar.SourceIP.DomainID | String | The ID of associated domain. | 
| QRadar.SourceIP.EventFlowCount | Number | The number of events and flows that are associated with the destination address. | 
| QRadar.SourceIP.FirstEventFlowSeen | Date | Date when the first event or flow was seen. | 
| QRadar.SourceIP.LastEventFlowSeen | Date | Date when the last event or flow was seen. | 
| QRadar.SourceIP.SourceIP | String | The IP address. | 
| QRadar.SourceIP.Magnitude | Number | The magnitude of the destination address. | 
| QRadar.SourceIP.Network | String | The network of the destination address. | 
| QRadar.SourceIP.OffenseIDs | Unknown | List of offense IDs the destination address is part of. | 
| QRadar.SourceIP.LocalDestinationAddressIDs | Unknown | List of local destination address IDs associated with the source address. | 

### qradar-ips-local-destination-get

***
Get Source IPs

#### Base Command

`qradar-ips-local-destination-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| local_destination_ip | Comma separated list. Local destination IPs to retrieve their data, E.g "192.168.0.1,192.160.0.2". | Optional | 
| filter | Query to filter IPs. E.g, filter=`local_destination_ip="192.168.0.1"` For reference please consult: https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html. | Optional | 
| fields | If used, will filter all fields except for the ones specified. Use this argument to specify which fields should be returned in the response. Fields that are not named are excluded. Specify subfields in brackets and multiple fields in the same object separated by commas. The filter uses QRadar's field names, for reference, consult: https://www.ibm.com/docs/en/qradar-common?topic=endpoints-get-siemlocal-destination-addresses. | Optional | 
| range | Range of results to return. e.g.: 0-20. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| QRadar.LocalDestinationIP.ID | Number | The ID of the destination address. | 
| QRadar.LocalDestinationIP.DomainID | String | The ID of associated domain. | 
| QRadar.LocalDestinationIP.EventFlowCount | Number | The number of events and flows that are associated with the destination address. | 
| QRadar.LocalDestinationIP.FirstEventFlowSeen | Date | Date when the first event or flow was seen. | 
| QRadar.LocalDestinationIP.LastEventFlowSeen | Date | Date when the last event or flow was seen. | 
| QRadar.LocalDestinationIP.LocalDestinationIP | String | The IP address. | 
| QRadar.LocalDestinationIP.Magnitude | Number | The magnitude of the destination address. | 
| QRadar.LocalDestinationIP.Network | String | The network of the destination address. | 
| QRadar.LocalDestinationIP.OffenseIDs | Unknown | List of offense IDs the destination address is part of. | 
| QRadar.LocalDestinationIP.SourceAddressIDs | Unknown | List of source address IDs associated with the destination address. | 

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and QRadar v3_copy corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.
2. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding event is closed in QRadar v3_copy.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and QRadar v3_copy.
