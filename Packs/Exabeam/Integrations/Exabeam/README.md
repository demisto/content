The Exabeam Security Management Platform provides end-to-end detection, User Event Behavioral Analytics and SOAR.
This integration was integrated and tested with version 53.5 of Exabeam.

### Authentication Methods
There are 2 authentication methods:
 - **API Token** - API token should be entered in the “API Token” parameter. In order to use the “Fetch Incident” functionality in this integration, the username must be provided also in the “Username” parameter.
 - **Basic Authentication** - Providing username and password in the corresponding parameters in the configuration. This method also allows fetching incidents.
 - ***Deprecated***:
 API Key entered in the “password” parameter and `__token` in the username parameter. This method won’t allow fetching incidents.

### Generate a Cluster Authentication Token

1. Navigate to **Settings** > **Admin Operations** > **Cluster Authentication Token**.

2. At the Cluster Authentication Token menu, click the blue `+` button.
   
3. In the **Setup Token** menu, fill in the **Token Name**, **Expiry Date**, and select the **Permission Level**(s).

4. Click **ADD TOKEN** to apply the configuration.

For additional information, refer to [Exabeam Administration Guide](https://docs.exabeam.com/en/advanced-analytics/i54/advanced-analytics-administration-guide/113254-configure-advanced-analytics.html#UUID-70a0411c-6ddc-fd2a-138d-fa83c7c59a40).

## Configure Exabeam in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g https://100.24.16.156:8484) |  | True |
| Username |  | False |
| Password |  | False |
| API Token | Cluster Authentication Token | False |
| Exabeam Incident Type | Incident type to filter in Exabeam. Possible values are: generic, abnormalAuth, accountManipulation, accountTampering, ueba, bruteForce, compromisedCredentials, cryptomining, dataAccessAbuse, dataExfiltration, dlp, departedEmployee, dataDestruction, evasion, lateralMovement, alertTriage, malware, phishing, privilegeAbuse, physicalSecurity, privilegeEscalation, privilegedActivity, ransomware, workforceProtection. | False |
| Priority | Incident priority to filter in Exabeam. Possible values are: low, medium, high, critical. | False |
| Status | Incident status to filter in Exabeam. Possible values are: closed, closedFalsePositive, inprogress, new, pending, resolved. | False |
| Fetch incidents |  | False |
| Max incidents per fetch |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Advanced: Minutes to look back when fetching | Use this parameter to determine how long backward to look in the search for incidents that were created before the last run time and did not match the query when they were created. Default is 1. | False |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |



### Fetch

#### Exabeam Incident

- Description: Information about incidents collected from the Exabeam system.
- Details: The incidents include details about events and actions identified in the Exabeam system, intended for monitoring and response.

#### Exabeam Notable User

- Description: Information about notable users collected from the Exabeam system.
- Details: Notable users are identified by the Exabeam system based on suspicious or abnormal behavior, and the information includes details about their actions in the system.
- Important: Duplicate notable users are never fetched unless the "Reset the 'last run' timestamp" button is pressed.

#### Note
The "Reset the 'last run' timestamp" button resets both the regular fetch and the Exabeam Notable User fetch.


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### exabeam-get-notable-users
***
Returns notable users in a period of time.


#### Base Command

`exabeam-get-notable-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_period | The time period for which to fetch notable users, such as 3 months, 2 days, 4 hours, 1 year, and so on. | Required | 
| limit | The maximum number of returned results. Default is 10. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.User.RiskScore | Number | The risk score of the notable user. | 
| Exabeam.User.UserFullName | String | The full name of the user. | 
| Exabeam.User.AverageRiskScore | Number | The average risk score of the user. | 
| Exabeam.User.FirstSeen | Date | The date the user was first seen. | 
| Exabeam.User.NotableSessionIds | String | The ID of the notable session. | 
| Exabeam.User.AccountsNumber | Number | The number of accounts. | 
| Exabeam.User.LastSeen | Date | The date the user was last seen. | 
| Exabeam.User.Location | String | The location of the user. | 
| Exabeam.User.UserName | String | The name of the user. | 
| Exabeam.User.Labels | String | The labels of the user. | 
| Exabeam.User.LastActivityType | String | The last activity type of the user. | 
| Exabeam.User.NotableUser | Boolean | Whether the user is a notable user. | 


#### Command Example
```!exabeam-get-notable-users limit=3 time_period="1 year"```

#### Human Readable Output
### Exabeam Notable Users:
|UserName|UserFullName|Title|Department|Labels|NotableSessionIds|EmployeeType|FirstSeen|LastSeen|LastActivity|Location|
|--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |
|username|fullname|Network Engineer|IT|privileged_user|session_id|employee|2018-08-01T11:50:16|2018-09-09T16:36:13|Account is active|Atlanta|
|username|fullname|Human Resources Coordinator|HR||session_id|employee|2018-07-03T14:26:26|2018-09-30T16:27:01|Account is active|Chicago|
|username|fullname|Sales Representative|Sales|privileged_user|session_id|employee|2018-08-10T15:55:25|2018-09-30T16:27:01|Account is active|Atlanta|


### exabeam-get-watchlists
***
Returns all watchlist IDs and titles.


#### Base Command

`exabeam-get-watchlists`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.Watchlist.Category | String | The watchlist category. | 
| Exabeam.Watchlist.Title | String | The watchlist title. | 
| Exabeam.Watchlist.WatchlistID | String | The watchlist ID. | 


#### Command Example
```!exabeam-get-watchlists```

#### Human Readable Output
### Exabeam Watchlists:
|WatchlistID|Title|Category|
|--- |--- |--- |
|5c869ab0315c745d905a26d9|Executive Users|UserLabels|
|5c869ab0315c745d905a26da|Service Accounts|UserLabels|
|5dbaba2dd4e62a0009dd7ae4|user watchlist|Users|
|5d8751723b72ea000830066a|VP Operations|PeerGroups|


### exabeam-get-peer-groups
***
Returns all peer groups.


#### Base Command

`exabeam-get-peer-groups`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.PeerGroup.Name | String | The name of the peer group. | 


#### Command Example
```!exabeam-get-peer-groups```

#### Human Readable Output
### Exabeam Peer Groups:
|Name|
|--- |
|Marketing|
|usa|
|101|
|Program Manager|
|Channel Administrator|
|Chief Marketing Officer|
|Chief Strategy Officer|


### exabeam-get-user-info
***
Returns user information data for the username.


#### Base Command

`exabeam-get-user-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the user to fetch. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.User.RiskScore | Number | The risk score of the user. | 
| Exabeam.User.AverageRiskScore | Number | The average risk score. | 
| Exabeam.User.PeerGroupFieldName | String | The field name of the peer group. | 
| Exabeam.User.FirstSeen | Date | The date when the user was first seen. | 
| Exabeam.User.PeerGroupDisplayName | String | The display name of the Peer group. | 
| Exabeam.User.LastSeen | Date | The date the user was last seen. | 
| Exabeam.User.PeerGroupFieldValue | String | The field value of the peer group. | 
| Exabeam.User.Label | String | The labels of the user. | 
| Exabeam.User.Username | String | The name of the user. | 
| Exabeam.User.PeerGroupType | String | The type of the peer group. | 
| Exabeam.User.LastSessionID | String | The last session ID of the user. | 
| Exabeam.User.LastActivityType | String | The last activity type of the user. | 
| Exabeam.User.AccountNames | String | The account name of the user. | 


#### Command Example
```!exabeam-get-user-info username={username}```

#### Human Readable Output
### User {username} information:
|Username|RiskScore|AverageRiskScore|LastSessionID|FirstSeen|LastSeen|LastActivityType|AccountNames|PeerGroupFieldName|PeerGroupFieldValue|PeerGroupDisplayName|PeerGroupType|
|--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |--- |
|{username}|163|102.53|{session_id}|2018-08-01T11:50:16|2018-09-09T16:36:13|Account is active|{account_name}|Peer Groups|root|root|Group|


### exabeam-get-user-labels
***
Returns all labels of the user.


#### Base Command

`exabeam-get-user-labels`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.UserLabel.Label | String | The label of the user. | 


#### Command Example
```!exabeam-get-user-labels```

#### Human Readable Output
### Exabeam User Labels:
|Label|
|--- |
|privileged_user|
|service_account|


### exabeam-get-user-sessions
***
Returns sessions for the given username and time range.


#### Base Command

`exabeam-get-user-sessions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username for which to fetch data. | Required | 
| start_time | The Start time of the time range. For example, 2018-08-01T11:50:16 or "30 days ago". | Optional | 
| end_time | The end time of the time range. For example, 2018-08-01T11:50:16 or "1 week ago". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.User.Session.EndTime | Date | The end time of the session. | 
| Exabeam.User.Session.InitialRiskScore | Number | The initial risk score of the session. | 
| Exabeam.User.Session.Label | String | The label of the session. | 
| Exabeam.User.Session.LoginHost | String | The login host. | 
| Exabeam.User.Session.RiskScore | Number | The risk score of the session. | 
| Exabeam.User.Session.SessionID | String | The ID of the session. | 
| Exabeam.User.Session.StartTime | Date | The start time of the session. | 
| Exabeam.User.Username | String | The username of the session. | 


#### Command Example
```!exabeam-get-user-sessions username={username} start_time=2018-08-01T11:50:16```

#### Human Readable Output
### User {username} sessions information:
|SessionID|RiskScore|InitialRiskScore|StartTime|EndTime|LoginHost|Label|
|--- |--- |--- |--- |--- |--- |--- |
|session_id|0|0|2018-08-01T14:05:46|2018-08-01T20:00:17|login_host||
|session_id|0|0|2018-08-01T23:17:00|2018-08-02T02:37:51|login_host|vpn-in|


### exabeam-delete-watchlist
***
Deletes a watchlist.


#### Base Command

`exabeam-delete-watchlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!exabeam-delete-watchlist watchlist_id=5de50f82088c6a000865408d```

#### Human Readable Output
The watchlist 5de50f82088c6a000865408d was deleted successfully.


### exabeam-get-asset-data
***
Returns asset data.


#### Base Command

`exabeam-get-asset-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_name | The name of the asset. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.Asset.HostName | String | The host name of the asset. | 
| Exabeam.Asset.IPAddress | String | The IP address of the asset. | 
| Exabeam.Asset.AssetType | String | Thr type of the asset. | 
| Exabeam.Asset.FirstSeen | Date | The date the asset was first seen. | 
| Exabeam.Asset.LastSeen | String | The date the asset was last seen. | 


#### Command Example
```!exabeam-get-asset-data asset_name={host_name}```

#### Human Readable Output
### Exabeam Asset Data:
|AssetType|FirstSeen|HostName|IPAddress|LastSeen|
|--- |--- |--- |--- |--- |
|Windows|2018-07-03T14:21:00|host_name|ip_address|2018-09-30T16:23:17|


### exabeam-get-session-info-by-id
***
Returns session info data for the given ID.


#### Base Command

`exabeam-get-session-info-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | ID of the session to fetch data for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.SessionInfo.sessionId | String | ID of the session. | 
| Exabeam.SessionInfo.username | String | Username of the session. | 
| Exabeam.SessionInfo.startTime | Date | Start time of the session. | 
| Exabeam.SessionInfo.endTime | Date | End time of the session. | 
| Exabeam.SessionInfo.initialRiskScore | Number | Initial risk score of the session. | 
| Exabeam.SessionInfo.riskScore | Number | Risk score of the session. | 
| Exabeam.SessionInfo.numOfReasons | Number | Number of rules in the session. | 
| Exabeam.SessionInfo.loginHost | String | The host from which the user was logged in. | 
| Exabeam.SessionInfo.label | String | Label of the session. | 
| Exabeam.SessionInfo.accounts | String | Accounts in the session. | 
| Exabeam.SessionInfo.numOfAccounts | Number | Number of accounts in the session. | 
| Exabeam.SessionInfo.numOfZones | Number | Number of zones in the session. | 
| Exabeam.SessionInfo.numOfAssets | Number | Number of assets in the session. | 
| Exabeam.SessionInfo.numOfEvents | Number | Number of events in the session. | 
| Exabeam.SessionInfo.numOfSecurityEvents | Number | Number of alerts in the session. | 
| Exabeam.SessionInfo.zones | Unknown | Zones information of the session. | 


#### Command Example
```!exabeam-get-session-info-by-id session_id=test-20200630233800```

#### Human Readable Output
### Session test-20200630233800 Information
|Accounts|End Time|Initial Risk Score|Login Host|Num Of Accounts|Num Of Assets|Num Of Events|Num Of Reasons|Num Of Security Events|Num Of Zones|Risk Score|Session Id|Start Time|Username|Zones|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| test | 2020-07-01T04:38:00 | 0 | test | 1 | 4 | 2 | 6 | 0 | 2 | 21 | test-20200630233800 | 2020-06-30T23:38:00 | test | los angeles office,<br/>chicago office |


### exabeam-list-top-domains
***
List top domains of a sequence.


#### Base Command

`exabeam-list-top-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sequence_id | ID of the sequence. | Required | 
| sequence_type | Type of the sequence. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.DataFeed.topDomains | Unknown | Top domains information. | 
| Exabeam.DataFeed.sequenceId | String | ID of the sequence. | 
| Exabeam.DataFeed.sequenceType | String | Type of the sequence. | 


#### Command Example
```!exabeam-list-top-domains sequence_id=test-20200630233800 sequence_type=session```

#### Human Readable Output
### Sequence test-20200630233800 Top Domains
**No entries.**


### exabeam-list-triggered-rules
***
Gets all the triggered rules of a sequence.


#### Base Command

`exabeam-list-triggered-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sequence_id | ID of the sequence to fetch data for. | Required | 
| sequence_type | Type of the sequence to fetch data for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.TriggeredRule._Id | String | UUID of the rule. | 
| Exabeam.TriggeredRule.ruleId | String | ID of the rule. | 
| Exabeam.TriggeredRule.ruleType | String | Type of the rule. | 
| Exabeam.TriggeredRule.eventId | String | Event ID of the rule. | 
| Exabeam.TriggeredRule.sessionId | String | Session ID of the rule. | 
| Exabeam.TriggeredRule.lockoutId | String | Lockout ID of the rule. | 
| Exabeam.TriggeredRule.sequenceId | String | Sequence ID of the rule. | 
| Exabeam.TriggeredRule.username | String | Username of the rule. | 
| Exabeam.TriggeredRule.eType | String | Event type of the rule. | 
| Exabeam.TriggeredRule.triggeringTime | Date | Time when the rule was triggered. | 
| Exabeam.TriggeredRule.riskScore | Number | Risk score of the rule. | 
| Exabeam.TriggeredRule.anchorScore | Number | Anchor score of the rule. | 
| Exabeam.TriggeredRule.anomalyFactor | Number | Anomaly factor of the rule. | 
| Exabeam.TriggeredRule.ruleData | Unknown | Data insight of the rule. | 
| Exabeam.TriggeredRule.createdTime | Date | Time when the rule was created. | 
| Exabeam.TriggeredRule.scoreData | Unknown | Score data of the rule. | 
| Exabeam.TriggeredRule.multiPeerGroupData | Unknown | Multi-peer group data of the triggered rule. | 


#### Command Example
```!exabeam-list-triggered-rules sequence_id=test-20200630233800 sequence_type=session```

#### Human Readable Output
### Sequence test-20200630233800 Triggered Rules
|_Id|anchorScore|anomalyFactor|createdTime|eType|eventId|riskScore|ruleData|ruleId|ruleType|scoreData|sessionId|triggeringTime|username|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 60072e97131b380006eb2208 | 15.0 | 1.0 | 2021-01-19T19:10:15.330000 | local-logon | 2311678@m | 15.0 | featureValue: tks_en_dd7_kt<br/>scopeValue: test<br/>modelName: LL-UH | LL-UH-F | session | histScoreData: {"weight": 1.0, "rawScore": 1.0585832492943268} | test-20200630233800 | 2020-06-30T23:38:00 | test |
| 60072e97131b380006eb220b | 15.0 | 0.28 | 2021-01-19T19:10:15.330000 | local-logon | 2311678@m | 4.27 | featureValue: tks_en_dd7_kt<br/>scopeValue: it administrator<br/>modelName: LL-GH | LL-GH-F | session | histScoreData: {"weight": 1.0, "rawScore": 0.6133293162851026} | test-20200630233800 | 2020-06-30T23:38:00 | test |
| 60072e97131b380006eb220d | 7.0 | 0.27 | 2021-01-19T19:10:15.330000 | local-logon | 2311678@m | 1.9 | featureValue: tks_en_dd7_kt<br/>scopeValue: salesforce<br/>modelName: LL-GH | LL-GH-A | session | histScoreData: {"weight": 1.0, "rawScore": 3.5486919149585874} | test-20200630233800 | 2020-06-30T23:38:00 | test |


### exabeam-get-asset-info
***
Returns asset information for given asset ID (hostname or IP address).


#### Base Command

`exabeam-get-asset-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the asset to fetch info for. | Required | 
| max_users_number | The maximal number of users. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.AssetInfo.assetId | String | ID of the asset. | 
| Exabeam.AssetInfo.hostName | String | Host of the asset. | 
| Exabeam.AssetInfo.ipAddress | String | IP address of the asset. | 
| Exabeam.AssetInfo.assetType | String | Type of the asset. | 
| Exabeam.AssetInfo.firstSeen | Date | Time when the asset was first seen. | 
| Exabeam.AssetInfo.lastSeen | Date | Time when the asset was last seen. | 
| Exabeam.AssetInfo.riskScore | Number | Risk score of the asset. | 
| Exabeam.AssetInfo.riskState | String | Risk state of the asset. | 
| Exabeam.AssetInfo.zone | String | Zone of the asset. | 
| Exabeam.AssetInfo.assetGroup | String | Group of the asset. | 
| Exabeam.AssetInfo.latestSequenceId | String | ID of the latest seqence of the asset. | 


#### Command Example
```!exabeam-get-asset-info asset_id=test_asset```

#### Human Readable Output
### Asset test_asset Information
|Asset Id|Asset Type|First Seen|Host Name|Ip Address|Last Seen|Latest Sequence Id|Risk Score|Zone|
|---|---|---|---|---|---|---|---|---|
| test_asset | Windows | 2020-06-01T14:41:00 | test_asset | 8.8.8.8 | 2020-07-02T19:58:00 | asset@test_asset-20200630 | 0.0 | new york office |


### exabeam-list-asset-timeline-next-events
***
Gets next events for a given asset.


#### Base Command

`exabeam-list-asset-timeline-next-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the asset. | Required | 
| event_time | The event time, e.g. "2 years ago" or "2019-02-27". | Required | 
| number_of_events | Preferred number of events. Default is 50. | Optional | 
| anomaly_only | Whether to return only anomaly events. Possible values are: true, false. Default is false. | Optional | 
| event_types | A comma-separated list of event types. | Optional | 
| event_types_operator | Whether or not to include the specified event types. Possible values are: include, exclude. Default is exclude. | Optional | 
| sequence_types | A comma-separated list of sequence types. | Required | 
| event_categories | A comma-separated list of event categories. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.AssetEvent.event_id | String | Event ID of the asset. | 
| Exabeam.AssetEvent.event_type | String | Type of the event. | 
| Exabeam.AssetEvent.event_category | String | Category of the event. | 
| Exabeam.AssetEvent.time | Date | Time when the event occurred. | 
| Exabeam.AssetEvent.rawlog_time | Date | Raw log time of the event. | 
| Exabeam.AssetEvent.session_id | String | Session ID of the event. | 
| Exabeam.AssetEvent.session_order | String | Session order of the event. | 
| Exabeam.AssetEvent.src_host | String | Source host of the event. | 
| Exabeam.AssetEvent.src_ip | String | Source IP of the event. | 
| Exabeam.AssetEvent.src_zone | String | Source zone of the event. | 
| Exabeam.AssetEvent.dest_host | String | Destination host of the event. | 
| Exabeam.AssetEvent.dest_ip | String | Destination IP of the event. | 
| Exabeam.AssetEvent.dest_zone | String | Destination of the event. | 
| Exabeam.AssetEvent.user | String | User of the event. | 
| Exabeam.AssetEvent.host | String | Host of the event. | 
| Exabeam.AssetEvent.domain | String | Domain of the event. | 
| Exabeam.AssetEvent.account | String | Account of the event. | 
| Exabeam.AssetEvent.hash | String | Hash of the event. | 
| Exabeam.AssetEvent.entity_asset_id | String | Entity asset ID of the event. | 
| Exabeam.AssetEvent.source | String | Source of the event. | 


#### Command Example
```!exabeam-list-asset-timeline-next-events asset_id=test_asset event_time="2 years ago" sequence_types=session```

#### Human Readable Output
# Asset test_asset Next Events
### 1 local-logon event(s) between 2020-06-01 15:29:00 and 2020-06-01 15:29:00
|Account|AuthPackage|AuthProcess|DestHost|DestIp|Domain|EntityAssetId|EventCategory|EventCode|EventId|EventType|Getvalue('ZoneInfo', Dest)|Hash|Host|IsSessionFirst|LogonTypeText|NonmachineUser|RawlogTime|SessionId|SessionOrder|Source|SrcHost|SrcIp|SrcZone|Time|User|UserSid|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| test_account1 | ntlm | Kerberos | tks_en_360_kt | 8.8.8.8 | kt_cloud | asset@test_asset-20200601 | user-events,<br/>asset-events | 4624 | 279@m | local-logon | zone55 | 1421552590 | dc_486 | true | 2 - Interactive | blozano | 2020-06-01T15:29:00 | blozano-20200601152900 | 1 | Windows | test_asset | 8.8.8.8 | los angeles office | 2020-06-01T15:29:00 | blozano | test_drive\blozano |

### 2 remote-access event(s) between 2020-06-01 16:00:00 and 2020-06-01 16:03:00
|Account|AssetFeature|AuthPackage|AuthProcess|DestHost|DestIp|Domain|EntityAssetId|EventCategory|EventCode|EventId|EventType|Getvalue('ZoneInfo', Dest)|Hash|Host|LogonTypeText|NtlmHost|RawlogTime|SessionId|SessionOrder|Source|SrcHost|SrcHostWindows|SrcIp|SrcZone|Time|User|UserSid|ZoneFeature|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| test_account1 | test_asset:test_asset2 | ntlm | Negotiate | test_asset2 | 8.8.8.8 | dev_kt | asset@test_asset-20200601 | user-events,<br/>asset-events | 4624 | 562@m | remote-access | chicago office | 1895168631 | dc_887 | 3 - Network | test_asset | 2020-06-01T16:00:00 | test_account1-20200601160000 | 2 | Windows | test_asset | test_asset | 8.8.8.8 | zone55 | 2020-06-01T16:00:00 | test_account1 | test_drive\test_account1 | zone55:chicago office |
| test_account2 | test_asset:test_asset3 | ntlm | Kerberos | test_asset3 | 8.8.8.8 | dev_kt | asset@test_asset-20200601 | user-events,<br/>asset-events | 4624 | 873@m | remote-access | zone55 | 1665078914 | dc_879 | 3 - Network | test_asset | 2020-06-01T16:02:00 | test_account2-20200601140600 | 3 | Windows | test_asset | test_asset | 8.8.8.8 | los angeles office | 2020-06-01T16:02:00 | test_account2 | test_drive\test_account2 | zone55:los angeles office |

### exabeam-list-security-alerts-by-asset
***
Gets security alerts for a given asset.


#### Base Command

`exabeam-list-security-alerts-by-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the asset to fetch info for. | Required | 
| sort_by | The key to sort results by. Possible values are: date, riskScore. Default is date. | Optional | 
| sort_order | The results order (ascending or descending). Possible values are: asc, desc. Default is desc. | Optional | 
| limit | Maximal number of results. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.AssetSecurityAlert.process | String | Process of the security alert. | 
| Exabeam.AssetSecurityAlert.process_name | String | Process name of the security alert. | 
| Exabeam.AssetSecurityAlert.alert_name | String | Name of the security alert. | 
| Exabeam.AssetSecurityAlert.alert_type | String | Type of the security alert. | 
| Exabeam.AssetSecurityAlert.alert_severity | String | Severity of the security alert. | 
| Exabeam.AssetSecurityAlert.malware_url | String | Malware URL of the security alert. | 
| Exabeam.AssetSecurityAlert.event_id | String | Event ID of the asset. | 
| Exabeam.AssetSecurityAlert.event_type | String | Type of the event. | 
| Exabeam.AssetSecurityAlert.time | Date | Time when the event occurred. | 
| Exabeam.AssetSecurityAlert.rawlog_time | Date | Raw log time of the security alert. | 
| Exabeam.AssetSecurityAlert.session_id | String | Session ID of the security alert. | 
| Exabeam.AssetSecurityAlert.session_order | String | Session order of the security alert. | 
| Exabeam.AssetSecurityAlert.src_host | String | Source host of the security alert. | 
| Exabeam.AssetSecurityAlert.src_ip | String | Source IP of the security alert. | 
| Exabeam.AssetSecurityAlert.src_port | String | Source port of the security alert. | 
| Exabeam.AssetSecurityAlert.dest_host | String | Destination host of the security alert. | 
| Exabeam.AssetSecurityAlert.dest_ip | String | Destination IP of the security alert. | 
| Exabeam.AssetSecurityAlert.dest_port | String | Destination port of the security alert. | 
| Exabeam.AssetSecurityAlert.user | String | User of the security alert. | 
| Exabeam.AssetSecurityAlert.host | String | Host of the security alert. | 
| Exabeam.AssetSecurityAlert.domain | String | Domain of the security alert. | 
| Exabeam.AssetSecurityAlert.account | String | Account of the security alert. | 
| Exabeam.AssetSecurityAlert.hash | String | Hash of the security alert. | 
| Exabeam.AssetSecurityAlert.MD5 | String | MD5 of the security alert. | 
| Exabeam.AssetSecurityAlert.entity_asset_id | String | Entity asset ID of the security alert. | 
| Exabeam.AssetSecurityAlert.source | String | Source of the security alert. | 
| Exabeam.AssetSecurityAlert.vendor | String | Vendor of the security alert. | 
| Exabeam.AssetSecurityAlert.sensor_id | Boolean | Sensor ID of the alert. | 
| Exabeam.AssetSecurityAlert.local_asset | String | Local asset of the security alert. | 
| Exabeam.AssetSecurityAlert.additional_info | String | Additional information about the security alert. | 


#### Command Example
```!exabeam-list-security-alerts-by-asset asset_id=lt-test_asset-888```

#### Human Readable Output
### Asset lt-test_asset-888 Security Alerts
|Account|Additional _ Info|Alert _ Id|Alert _ Name|Alert _ Severity|Alert _ Type|Dest _ Host|Dest _ Ip|Dest _ Port|Entity _ Asset _ Id|Event _ Id|Event _ Type|Hash|Host|Local _ Asset|Malware _ Url|Md 5|Process|Process _ Name|Rawlog _ Time|Sensor _ Id|Session _ Id|Session _ Order|Source|Src _ Dest _ Alert|Src _ Host|Src _ Ip|Src _ Port|Time|User|Vendor|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| test_account |   default_taxes: | 1956 | test1 | 4 | Export-ReportView-Contact | tks_en_eff_kt | 8.8.8.8 | 1117 | asset@lt-test_asset-888-20200613,<br/>asset@tks_en_eff_kt-20200613,<br/>asset@10.37.0.17-20200613,<br/>asset@192.168.16.137-20200613 | 968178@m | security-alert | 781895093 | dc_936 | lt-test_asset-888 | test.com | e62ef0ed95b79d4c6327d410cb8100348c | test.exe | test.exe | 2020-06-13T17:25:00 | 0xun6f | test_asset-20200613154800 | 22 | Palo Alto Networks WildFire | Backdoor-FFBM:lt-test_asset-888:tks_en_eff_kt | lt-test_asset-888 | 8.8.8.8 | 1204 | 2020-06-13T17:25:00 | test_asset | Palo Alto Networks WildFire |
| test_account |  * **Pull Request**: [] | 3770 | test2 | LOW | Export-Report | tks_en_0b3_kt | 8.8.8.8 | 105 | asset@lt-test_asset-888-20200613,<br/>asset@tks_en_0b3_kt-20200613,<br/>asset@10.37.0.17-20200613,<br/>asset@10.136.0.55-20200613 | 954176@m | security-alert | 1734360022 | dc_936 | lt-test_asset-888 | http://test.com/ | 1c30fae6dadda43962e2444445d3f87f70 | test.exe | test.exe | 2020-06-13T16:16:00 | 0x6m5w | test_asset-20200613154800 | 6 | Palo Alto Networks WildFire | Exploit/CVE-2015-1539:lt-test_asset-888:tks_en_0b3_kt | lt-test_asset-888 | 8.8.8.8 | 1204 | 2020-06-13T16:16:00 | test_asset | Palo Alto Networks WildFire |

### exabeam-search-rules
***
Searches for rules by a keyword.


#### Base Command

`exabeam-search-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keyword | The search keyword. | Required | 
| filter | The search filter. | Optional | 
| limit | Maximal number of rules to retrieve. Default is 50. | Optional | 
| page | Results page number. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.Rule.categoryId | String | Category ID of the rule. | 
| Exabeam.Rule.categoryDisplayName | String | Category display name of the rule. | 
| Exabeam.Rule.ruleId | String | ID of the rule. | 
| Exabeam.Rule.ruleDef.ruleName | String | Name of the rule. | 
| Exabeam.Rule.ruleDef.ruleDescription | String | Description of the rule. | 
| Exabeam.Rule.ruleDef.reasonTemplate | String | Reason template of the rule. | 
| Exabeam.Rule.ruleDef.aggregateReasonTemplate | String | Aggregate reason template of the rule. | 
| Exabeam.Rule.ruleDef.ruleType | String | Type of the rule. | 
| Exabeam.Rule.ruleDef.classifyIf | String | Classification definition of the rule. | 
| Exabeam.Rule.ruleDef.ruleEventTypes | String | Event types of the rule. | 
| Exabeam.Rule.ruleDef.disabled | Boolean | Whether or not the rule is disabled. | 
| Exabeam.Rule.ruleDef.modelName | String | Model name of the rule. | 
| Exabeam.Rule.ruleDef.factFeatureName | String | Fact feature name of the rule. | 
| Exabeam.Rule.ruleDef.hasDynamicScore | Boolean | Whether or not the rule has a dynamic score. | 
| Exabeam.Rule.ruleDef.score | Number | Score of the rule. | 
| Exabeam.Rule.ruleDef.percentileThreshold | String | Percentile threshold of the rule. | 
| Exabeam.Rule.ruleDef.ruleExpression | String | The rule expression. | 
| Exabeam.Rule.ruleDef.dependencyExpression | String | The rule dependency expression. | 
| Exabeam.Rule.ruleDef.ruleCategory | String | The category of the rule. | 
| Exabeam.Rule.disabled | Boolean | Whether or not the rule is disabled. | 
| Exabeam.Rule.effective | Boolean | True if the rule is effective, false otherwise. | 
| Exabeam.Rule.state | String | State of the rule \(DefaultExabeam, ModifiedExabeam or CustomerCreated\). | 
| Exabeam.Rule.canSimpleEdit | Boolean | Whether or not it is possible to use the simple editor on this rule. | 


#### Command Example
```!exabeam-search-rules limit=1 keyword=account```

#### Human Readable Output
### Rule Search Results
|Can Simple Edit|Category Display Name|Category Id|Disabled|Effective|Rule Def|Rule Id|State|
|---|---|---|---|---|---|---|---|
| false | Account Creation and Management | Account Creation and Management | false | true | ruleId: AM-GOU-A<br/>ruleName: Abnormal account OU addition to this group<br/>ruleDescription: OU means Organizational Unit - a container within a Microsoft Active Directory domain which can hold users, groups, and computers. Account management events are notable because they can provide a path for an attacker to move laterally through a system.<br/>reasonTemplate: Abnormal account OU {default\|event.account_ou} addition to group {default\|event.group_name}<br/>aggregateReasonTemplate: Abnormal account OU addition to this group: {default\|featureValue\|histogram}<br/>ruleType: session<br/>classifyIf: (count(account_ou, 'member-added') = 1)<br/>ruleEventTypes: member-added<br/>disabled: false<br/>modelName: AM-GOU<br/>factFeatureName: account_ou<br/>hasDynamicScore: false<br/>score: 7.0<br/>percentileThreshold: 0.1<br/>ruleExpression: ((confidence_factor >= 0.8) && ((num_observations > 0) && (num_observations &lt; percentile_threshold_count)))<br/>dependencyExpression: NA<br/>ruleCategory: Account Creation and Management<br/>ruleLabels:  | AM-GOU-A | ModifiedExabeam |

### exabeam-get-rule-string
***
Gets a rule's information as a string.


#### Base Command

`exabeam-get-rule-string`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_id | The ID of the rule. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.Rule.ruleId | String | The ID of the rule. | 
| Exabeam.Rule.ruleString | String | The rule string. | 


#### Command Example
```!exabeam-get-rule-string rule_id=AM-GOU-A```

#### Human Readable Output
### Rule AM-GOU-A String
|Rule Id|Rule String|
|---|---|
| AM-GOU-A | AM-GOU-A {<br/>  RuleName = "Abnormal account OU addition to this group"<br/>  RuleDescription = "OU means Organizational Unit - a container within a Microsoft Active Directory domain which can hold users, groups, and computers. Account management events are notable because they can provide a path for an attacker to move laterally through a system."<br/>  ReasonTemplate = "Abnormal account OU {default\|event.account_ou} addition to group {default\|event.group_name}"<br/>  AggregateReasonTemplate = "Abnormal account OU addition to this group: {default\|featureValue\|histogram}"<br/>  RuleType = "session"<br/>  RuleCategory = "Account Creation and Management"<br/>  ClassifyIf = "count(account_ou,'member-added')=1"<br/>  RuleEventTypes = ["member-added"]<br/>  Disabled = "FALSE"<br/>  Model = "AM-GOU"<br/>  FactFeatureName = "account_ou"<br/>  Score = "7"<br/>  HistShapeScoring {<br/>    Enabled = true<br/>  }<br/>  PercentileThreshold = "0.1"<br/>  RuleExpression = "confidence_factor>=0.8 && num_observations>0 && num_observations &lt;percentile_threshold_count"<br/>  DependencyExpression = "NA"<br/>  RuleLabels {<br/>    mitre = ["T1078"]<br/>  }<br/>} |


### exabeam-fetch-rules
***
Gets all rules.


#### Base Command

`exabeam-fetch-rules`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter_by | The type of the rules to retrieve. Possible values are: all, custom, default. Default is all. | Optional | 
| page | Which page of results to return. Default is 0. | Optional | 
| limit | Maximal number of results. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.Rule.categoryId | String | Category ID of the rule. | 
| Exabeam.Rule.categoryDisplayName | String | Category display name of the rule. | 
| Exabeam.Rule.ruleId | String | ID of the rule. | 
| Exabeam.Rule.ruleDef.ruleName | String | Name of the rule. | 
| Exabeam.Rule.ruleDef.ruleDescription | String | Description of the rule. | 
| Exabeam.Rule.ruleDef.reasonTemplate | String | Reason template of the rule. | 
| Exabeam.Rule.ruleDef.aggregateReasonTemplate | String | Aggregate reason template of the rule. | 
| Exabeam.Rule.ruleDef.ruleType | String | Type of the rule. | 
| Exabeam.Rule.ruleDef.classifyIf | String | Classification expression definition of the rule. | 
| Exabeam.Rule.ruleDef.ruleEventTypes | String | Event types of the rule. | 
| Exabeam.Rule.ruleDef.disabled | Boolean | Whether or not the rule is disabled. | 
| Exabeam.Rule.ruleDef.modelName | String | Model name that the rule references. | 
| Exabeam.Rule.ruleDef.factFeatureName | String | The name of a feature used for fact based rules. | 
| Exabeam.Rule.ruleDef.hasDynamicScore | Boolean | Whether or not the rule has a dynamic score. | 
| Exabeam.Rule.ruleDef.score | Number | Score of the rule. | 
| Exabeam.Rule.ruleDef.percentileThreshold | String | Indicates which observations are considered anomalous based on the histogram. | 
| Exabeam.Rule.ruleDef.ruleExpression | String | A boolean expression that the rule engine uses to determine if a particular rule will trigger. | 
| Exabeam.Rule.ruleDef.dependencyExpression | String | The rule dependency expression. | 
| Exabeam.Rule.ruleDef.ruleCategory | String | The category of the rule. | 
| Exabeam.Rule.disabled | Boolean | Whether or not the rule is disabled. | 
| Exabeam.Rule.effective | Boolean | True if the rule is effective, false otherwise. | 
| Exabeam.Rule.state | String | State of the rule \(DefaultExabeam, ModifiedExabeam or CustomerCreated\). | 
| Exabeam.Rule.canSimpleEdit | Boolean | Whether or not it is possible to use the simple editor on this rule. | 


#### Command Example
```!exabeam-fetch-rules limit=1```

#### Human Readable Output
### Rule Search Results
|Can Simple Edit|Category Display Name|Category Id|Disabled|Effective|Rule Def|Rule Id|State|
|---|---|---|---|---|---|---|---|
| false | Account Creation and Management | Account Creation and Management | false | true | ruleId: AM-GOU-A<br/>ruleName: Abnormal account OU addition to this group<br/>ruleDescription: OU means Organizational Unit - a container within a Microsoft Active Directory domain which can hold users, groups, and computers. Account management events are notable because they can provide a path for an attacker to move laterally through a system.<br/>reasonTemplate: Abnormal account OU {default\|event.account_ou} addition to group {default\|event.group_name}<br/>aggregateReasonTemplate: Abnormal account OU addition to this group: {default\|featureValue\|histogram}<br/>ruleType: session<br/>classifyIf: (count(account_ou, 'member-added') = 1)<br/>ruleEventTypes: member-added<br/>disabled: false<br/>modelName: AM-GOU<br/>factFeatureName: account_ou<br/>hasDynamicScore: false<br/>score: 7.0<br/>percentileThreshold: 0.1<br/>ruleExpression: ((confidence_factor >= 0.8) && ((num_observations > 0) && (num_observations &lt; percentile_threshold_count)))<br/>dependencyExpression: NA<br/>ruleCategory: Account Creation and Management<br/>ruleLabels:  | AM-GOU-A | ModifiedExabeam |


### exabeam-get-rules-model-definition
***
Gets a rule model definition by name.


#### Base Command

`exabeam-get-rules-model-definition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model_name | The name of the model. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.Model.alpha | String | Alpha value of the model. | 
| Exabeam.Model.name | String | Name of the model. | 
| Exabeam.Model.feature | String | Feature of the model. | 
| Exabeam.Model.cutOff | String | Cut off value of the model. | 
| Exabeam.Model.histogramEventTypes | String | Histogram event types of the model. | 
| Exabeam.Model.featureName | String | Feature name of the model. | 
| Exabeam.Model.description | String | Description of the model. | 
| Exabeam.Model.trainIf | String | Train if expression definition of the model. | 
| Exabeam.Model.featureType | String | Feature type of the model. | 
| Exabeam.Model.modelTemplate | String | The model template. | 
| Exabeam.Model.convergenceFilter | String | Convergence filter of the model. | 
| Exabeam.Model.iconName | String | Icon name of the model. | 
| Exabeam.Model.modelType | String | Type of the model. | 
| Exabeam.Model.binWidth | String | The bin width. | 
| Exabeam.Model.maxNumberOfBins | String | The maximal number of bins. | 
| Exabeam.Model.scopeType | String | The scope type of the model. | 
| Exabeam.Model.agingWindow | String | Aging window of the model. | 
| Exabeam.Model.category | String | The model category. | 
| Exabeam.Model.disabled | String | TRUE if the model is disabled, FALSE otherwise. | 
| Exabeam.Model.scopeValue | String | The scope value of the model. | 


#### Command Example
```!exabeam-get-rules-model-definition model_name=AM-AG```

#### Human Readable Output
### Model AM-AG Definition
|Aging Window|Alpha|Category|Convergence Filter|Cut Off|Description|Disabled|Feature|Feature Name|Feature Type|Histogram Event Types|Max Number Of Bins|Model Template|Model Type|Name|Scope Type|Scope Value|Train If|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 32 | 0.8 | Other | confidence_factor>=0.8 | 5 | Models which security groups users are being added to in the organization | FALSE | group_name | group_name | group_name | member-added | 1000000 | Account management, groups which users are being added to | CATEGORICAL | AM-AG | ORG | org | TRUE |


### exabeam-watchlist-add-items
***
Add watchlist items by their names or from a CSV file.


#### Base Command

`exabeam-watchlist-add-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. | Required | 
| items | A comma-separated list of the items to add. | Optional | 
| csv_entry_id | The entry ID of the CSV file. | Optional | 
| watch_until_days | Number of days until asset is automatically removed from the watchlist. Default is 50. | Optional | 
| category | The item category. Possible values are: Anomalies, Assets, Events, Sessions, Users. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!exabeam-watchlist-add-items category=Assets watchlist_id=60249dfb130b3800075b8e36 items=asset1,asset2```

#### Human Readable Output
Successfully added 2 items to watchlist 60249dfb130b3800075b8e36.


### exabeam-watchlist-asset-search
***
Gets the assets of a specified watchlist according to a keyword.


#### Base Command

`exabeam-watchlist-asset-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keyword | A keyword to search. | Required | 
| watchlist_id | The watchlist ID. | Required | 
| limit | Maximum number of results to retrieve. Default is 30. | Optional | 
| is_exclusive | Whether or not the item is exclusive on watchlist. Possible values are: true, false. Default is false. | Optional | 
| search_by_ip | Whether or not to search the item by its IP. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.AssetInfo.hostName | String | Host of the asset. | 
| Exabeam.AssetInfo.ipAddress | String | IP address of the asset. | 
| Exabeam.AssetInfo.assetType | String | Type of the asset. | 
| Exabeam.AssetInfo.firstSeen | Date | Time when the asset was first seen. | 
| Exabeam.AssetInfo.lastSeen | Date | Time when the asset was last seen. | 
| Exabeam.AssetInfo.riskScore | Number | Risk score of the asset. | 
| Exabeam.AssetInfo.riskState | String | Risk state of the asset. | 
| Exabeam.AssetInfo.zone | String | Zone of the asset. | 


#### Command Example
```!exabeam-watchlist-asset-search watchlist_id=60249dfb130b3800075b8e36 keyword=s```

#### Human Readable Output
### Watchlist 60249dfb130b3800075b8e36 Assets Search Results
|Asset Type|First Seen|Host Name|Ip Address|Last Seen|Risk Score|Risk State|Zone|
|---|---|---|---|---|---|---|---|
| Windows | 2020-06-01T15:01:00 | asset1 | 8.8.8.8 | 2020-07-03T23:16:00 | 0.0 | compromised | atlanta office |
| Windows | 2020-06-01T14:17:00 | asset2 |  | 2020-07-03T23:45:00 | 140.0 | compromised |  |


### exabeam-watchlist-remove-items
***
Removes items from a watchlist.


#### Base Command

`exabeam-watchlist-remove-items`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| watchlist_id | The watchlist ID. | Required | 
| items | A comma-separated list of the items to remove. | Required | 
| category | The category of the items to remove. Possible values are: Anomalies, Assets, Events, Sessions, Users. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!exabeam-watchlist-remove-items category=Assets watchlist_id=60249dfb130b3800075b8e36 items=asset1,asset2```

#### Human Readable Output
Successfully removed 2 items from watchlist 60249dfb130b3800075b8e36.


### exabeam-list-context-table-records
***
Returns a list of a context table records.


#### Base Command

`exabeam-list-context-table-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context_table_name | The name of the context table. | Required | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| offset | The offset number to begin (starts from 1). Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.ContextTable.Name | String | Name of the context table. | 
| Exabeam.ContextTable.Record.key | String | The key of the record. | 
| Exabeam.ContextTable.Record.id | String | The ID of the record. | 
| Exabeam.ContextTable.Record.sourceType | String | The source type of the record. | 
| Exabeam.ContextTable.Record.position | Number | The position of the record. | 
| Exabeam.ContextTable.Record.value | String | Value of the record. | 


#### Command Example
```!exabeam-list-context-table-records context_table_name=test_table```

#### Human Readable Output
### Context Table `test_table` Records
|Id|Position|Source Type|Key|Value|
|---|---|---|---|---|
| 0-0 | 0 | Manual | ktest2 | v3 |
| 0-1 | 1 | Manual | ktest3 |  |
| 0-2 | 2 | Manual | ktest4 | v4 |
| 0-3 | 3 | Manual | k1 | v1,<br/>v2,<br/>v3 |



### exabeam-add-context-table-records
***
Add records to the context table.


#### Base Command

`exabeam-add-context-table-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context_table_name | The name of the context table. | Required | 
| records | A comma-separated list of records to add, for example: k1,k2. If context_table_type argument is set to key_value, every record should be in "key:values" format, where "values" is a semi-colon separated list of values. For example: k1:v1;v2,k2:v3,k3:,k4:v4. | Required | 
| session_id | The ID of update session. If not specified, a new session is created. | Optional | 
| context_table_type | The context table type. Possible values are: key_only, key_value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.ContextTableUpdate.contextTableName | String | The context table name. | 
| Exabeam.ContextTableUpdate.sessionId | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.changeType | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.changeId | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.record.key | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.record.value | Unknown | The raw data of the context table update. | 


#### Command Example
```!exabeam-add-context-table-records context_table_name=test_table context_table_type=key_value records=testk1:v1,testv2:,testv3:v31;v32```

#### Human Readable Output
### Context Table test_do_not_remove Update Details
createdSize: 3, updatedSize: 0, removedSize: 0, duplicates: []
|Change Id|Change Type|Context Table Name|Record|Session Id|
|---|---|---|---|---|
| 45dc28dc-28be-426c-9293-d7f477f85408 | created | test_table | key: testk1<br/>value: v1 | f0283c9c-7317-457b-b9de-43888960b4cb |
| 1c96f414-dc0e-4106-a972-05dbbb77dd63 | created | test_table | key: testv2<br/>value:  | f0283c9c-7317-457b-b9de-43888960b4cb |
| 0a2ca93c-e5da-442c-adcd-5c7af2df9b13 | created | test_table | key: testv3<br/>value: v31,<br/>v32 | f0283c9c-7317-457b-b9de-43888960b4cb |


### exabeam-update-context-table-records
***
Updates records of a context table.


#### Base Command

`exabeam-update-context-table-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context_table_name | The name of the context table. | Required | 
| session_id | The ID of update session. If not specified, a new session is created. | Optional | 
| records | A comma-separated list of records to update. If context_table_type argument is set to key_only, each record should be in the following format: id:key. Otherwise it's a key_value type and then the format of a record is id:key:values, where the values are separated by semi-colons. | Required | 
| context_table_type | Type of the context table. Possible values are: key_only, key_value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.ContextTableUpdate.contextTableName | String | The context table name. | 
| Exabeam.ContextTableUpdate.sessionId | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.changeType | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.changeId | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.record.key | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.record.value | Unknown | The raw data of the context table update. | 


#### Command Example
```!exabeam-update-context-table-records context_table_name=test_key_only context_table_type=key_only records=0-0:test,0-1:test1```

#### Human Readable Output
### Context Table test_key_only Update Details
createdSize: 0, updatedSize: 2, removedSize: 0, duplicates: []
|Change Id|Change Type|Context Table Name|Record|Session Id|
|---|---|---|---|---|
| 9be31efc-0aac-4c56-98e1-dedec68f32dd | updated | test_key_only | key: test<br/>id: 0-0 | fdf0fd02-bf87-4c03-ad09-cc53e4c8aaee |
| 744b59ee-0f53-4e1f-8bfc-fcdcc9a8c568 | updated | test_key_only | key: test1<br/>id: 0-1 | fdf0fd02-bf87-4c03-ad09-cc53e4c8aaee |



### exabeam-get-context-table-in-csv
***
Export a context table to CSV.


#### Base Command

`exabeam-get-context-table-in-csv`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context_table_name | Name of the context table. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!exabeam-get-context-table-in-csv context_table_name=test_table```


### exabeam-add-context-table-records-from-csv
***
Add context table records from CSV file in a specific modification session.


#### Base Command

`exabeam-add-context-table-records-from-csv`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context_table_name | Name of the context table. | Required | 
| session_id | The ID of context table session. If not specified, a new session is created. | Optional | 
| has_header | Indicates whether the file has a header. Possible values are: true, false. | Required | 
| file_entry_id | The entry ID of the CSV file from which records will be added. | Required | 
| append_or_replace | Whether to replace or append the records from the CSV file. Possible values are: append, replace. Default is append. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!exabeam-add-context-table-records-from-csv context_table_name=test_table file_entry_id=2034d0d-86ad-04bc3dfa1272 has_header=true append_or_replace=append```

#### Human Readable Output
### Context Table test_table Update Details
createdSize: 2, updatedSize: 0, removedSize: 0, duplicates: []
|Change Id|Change Type|Context Table Name|Record|Session Id|
|---|---|---|---|---|
| 4a376a74-7f02-49cc-ac37-d73f37ba7809 | created | test_table | key: k33<br/>value: 1 | 15b2499c-8506-48ed-9431-7dce94de33a2 |
| 37733fb6-e947-4b07-b240-9c5602317d55 | created | test_table | key: k44<br/>value: 2,3 | 15b2499c-8506-48ed-9431-7dce94de33a2 |


### exabeam-delete-context-table-records
***
Delete records from a context table.


#### Base Command

`exabeam-delete-context-table-records`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| context_table_name | Name of the context table. | Required | 
| records | A comma-separated list of the records' keys to delete. | Required | 
| session_id | The ID of update session. If not specified, a new session is created. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.ContextTableUpdate.contextTableName | String | The context table name. | 
| Exabeam.ContextTableUpdate.sessionId | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.changeType | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.changeId | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.record.key | Unknown | The raw data of the context table update. | 
| Exabeam.ContextTableUpdate.record.value | Unknown | The raw data of the context table update. | 


#### Command Example
```!exabeam-delete-context-table-records context_table_name=test_table context_table_type=key_value records=testk11,testv2```

#### Human Readable Output
### Context Table test_table Update Details
createdSize: 0, updatedSize: 0, removedSize: 2, duplicates: []
|Change Id|Change Type|Context Table Name|Record|Session Id|
|---|---|---|---|---|
| e4469b52-ac45-4c97-91af-16c31b8fbb49 | removed | test_table | key: <br/>id: testk11 | 64e660b7-5f70-40df-adf7-3e8a4bf25462 |
| 5137afa2-36d4-4818-93ec-f3fd0e244c38 | removed | test_table | key: <br/>id: testv2 | 64e660b7-5f70-40df-adf7-3e8a4bf25462 |


#### Base Command

`exabeam-get-notable-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of returned results. | Required | 
| time_period | The time period for which to fetch notable users, such as 3 months, 2 days, 4 hours, 1 year, and so on. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.NotableAsset.HostName | String | The notable asset host name. | 
| Exabeam.NotableAsset.IPAddress | String | The notable asset IP address. | 
| Exabeam.NotableAsset.AssetType | String | The notable asset type. | 
| Exabeam.NotableAsset.FirstSeen | Date | Time when the asset was first seen. | 
| Exabeam.NotableAsset.LastSeen | Date | Time when the asset was last seen. | 
| Exabeam.NotableAsset.highestRiskScore | Number | The highest risk score of the asset. | 
| Exabeam.NotableAsset.id | String | The notable asset ID. | 
| Exabeam.NotableAsset.entityName | String | The entity name of the asset. | 
| Exabeam.NotableAsset.entityValue | String | The entity value of the asset. | 
| Exabeam.NotableAsset.day | Date | The notable asset date. | 
| Exabeam.NotableAsset.triggeredRuleCountOpt | Number | The number that asset triggered rule count opt. | 
| Exabeam.NotableAsset.riskScoreOpt | Number | Risk score opt of the asset. | 
| Exabeam.NotableAsset.incidentIds | Unknown | The incident IDs of the notable asset. | 
| Exabeam.NotableAsset.commentId | String | The comment ID of the notable asset. | 
| Exabeam.NotableAsset.commentType | String | The comment type of the notable asset. | 
| Exabeam.NotableAsset.commentObjectId | String | The comment object ID of the notable asset. | 
| Exabeam.NotableAsset.text | String | The notable asset text. | 
| Exabeam.NotableAsset.exaUser | String | The notable asset exaUser. | 
| Exabeam.NotableAsset.exaUserFullname | String | The notable asset exaUser fullname. | 
| Exabeam.NotableAsset.createTime | Date | Time when the asset was created. | 
| Exabeam.NotableAsset.updateTime | Date | Time when the asset was updated. | 
| Exabeam.NotableAsset.edited | Boolean | Whether or not the notable asset is edited. | 
| Exabeam.NotableAsset.zone | String | The number that asset triggered rule count opt. | 


#### Command Example
```!exabeam-get-notable-assets limit=1 time_period="1 day"```


### exabeam-get-notable-session-details
***
Returns notable session details.


#### Base Command

`exabeam-get-notable-session-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the asset to fetch info for. | Required | 
| sort_by | The key to sort results by. Possible values are: date, riskScore. Default is date. | Optional | 
| sort_order | The order of the results (ascending or descending). Possible values are: asc, desc. Default is desc. | Optional | 
| limit | Maximum number of results. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.NotableSession.users.UserName | String | The notable session user name. | 
| Exabeam.NotableSession.users.RiskScore | number | The notable session risk score. | 
| Exabeam.NotableSession.users.AverageRiskScore | number | The average risk score of the notable session. | 
| Exabeam.NotableSession.users.FirstSeen | Date | Time when the notable session was first seen. | 
| Exabeam.NotableSession.users.LastSeen | Date | Time when the notable session was last seen. | 
| Exabeam.NotableSession.users.lastActivityType | String | The last activity type of the user. | 
| Exabeam.NotableSession.users.Labels | Unknown | The labels of the user. | 
| Exabeam.NotableSession.users.LastSessionID | String | The last session ID of the user. | 
| Exabeam.NotableSession.users.EmployeeType | String | The employee type of the user. | 
| Exabeam.NotableSession.users.Department | String | The department of the user. | 
| Exabeam.NotableSession.users.Title | String | The role of the user. | 
| Exabeam.NotableSession.users.Location | String | The location of the user. | 
| Exabeam.NotableSession.users.Email | String | The email of the user. | 
| Exabeam.NotableSession.sessions.SessionID | String | The Session ID. | 
| Exabeam.NotableSession.sessions.InitialRiskScore | Number | Initial risk score of the session. | 
| Exabeam.NotableSession.sessions.LoginHost | String | The host from which the user was logged in. | 
| Exabeam.NotableSession.sessions.Accounts | String | Accounts in the session. | 
| Exabeam.NotableSession.executiveUserFlags | Unknown | Whether the user is a executive user. | 


#### Command Example
```!exabeam-get-notable-session-details asset_id=asset_id sort_by=date sort_order=asc limit=1```


### exabeam-get-notable-sequence-details
***
Returns sequence details for the given asset ID and time range.


#### Base Command

`exabeam-get-notable-sequence-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | The asset ID for which to fetch data. | Required | 
| start_time | The Start time of the time range. For example, 2018-08-01T11:50:16. | Optional | 
| end_time | The end time of the time range. For example, 2018-08-01T11:50:16. | Optional | 
| limit | Maximum number of rules to retrieve. Default is 50. | Optional | 
| page | Results page number. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.Sequence.sequenceId | String | The ID of the sequence. | 
| Exabeam.Sequence.isWhitelisted | Boolean | Whether or not the sequence is on allow list. | 
| Exabeam.Sequence.areAllTriggeredRulesWhiteListed | Boolean | Whether or not the sequence are all triggered rules allow listed. | 
| Exabeam.Sequence.hasBeenPartiallyWhiteListed | Boolean | Whether or not the sequence has been partially allow listed. | 
| Exabeam.Sequence.riskScore | Number | The sequence risk score. | 
| Exabeam.Sequence.startTime | Date | Start time of the sequence. | 
| Exabeam.Sequence.endTime | Date | End time of the sequence. | 
| Exabeam.Sequence.numOfReasons | Number | Number of reasons in the sequence. | 
| Exabeam.Sequence.numOfEvents | Number | Number of events in the sequence. | 
| Exabeam.Sequence.numOfUsers | Number | Number of users in the sequence. | 
| Exabeam.Sequence.numOfSecurityEvents | Number | Number of security events in the sequence. | 
| Exabeam.Sequence.numOfZones | Number | Number of zones in the sequence. | 
| Exabeam.Sequence.numOfAssets | Number | Number of assets in the sequence. | 
| Exabeam.Sequence.assetId | String | The asset ID of the sequence. | 


#### Command Example
```!exabeam-get-notable-sequence-details asset_id=asset_id start_time="30 days"```


### exabeam-get-sequence-eventtypes
***
Returns sequence event types for the given asset sequence ID and time range.


#### Base Command

`exabeam-get-sequence-eventtypes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_sequence_id | The asset sequence ID. | Required | 
| search_str | String to search for inside display name. | Optional | 
| limit | Maximum number of rules to retrieve. Default is 50. | Optional | 
| page | Results page number. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Exabeam.SequenceEventTypes.eventType | String | The sequence event type. | 
| Exabeam.SequenceEventTypes.displayName | String | The sequence display name. | 
| Exabeam.SequenceEventTypes.count | Number | The number of the sequences. | 
| Exabeam.SequenceEventTypes.sequenceId | String | The sequence ID. | 


#### Command Example
```!exabeam-get-sequence-eventtypes asset_sequence_id=asset_sequence_id search_str="search_str"```


### exabeam-list-incident
***
Returns incidents from Exabeam.

#### Base Command

`exabeam-list-incident`
#### Input

| **Argument Name** | **Description**                                                            | **Required** |
|-------------------|----------------------------------------------------------------------------| --- |
| incident_id       | The incident ID.                                                           | Optional | 
| query             | Query string which is a combination of incident type, priority and status. | Optional | 
| incident_type     | Incident type to filter in Exabeam.                        | Optional | 
| priority          | Incident priority to filter in Exabeam.                  | Optional |
| status            | Incident status to filter in Exabeam.                    | Optional |
| limit             | Maximum number of rules to retrieve. Default is 50.                        | Optional | 
| page_size         | Number of total results in each page. Default is 25.                                         | Optional | 
| page_number       | Specific page to query.                                  | Optional |
| username       | When the instance is configure by an API key, it must be used with the username argument.                                  | Optional |


#### Context Output

| **Path**                              | **Type** | **Description**                  |
|---------------------------------------| --- |----------------------------------|
| Exabeam.incidents.incidentId          | String | The ID of the incident.          | 
| Exabeam.incidents.name                | String | The name of the incident.        | 
| Exabeam.incidents.fields.startedDate  | Date | The starting date of the incident.     | 
| Exabeam.incidents.fields.closedDate   | Date | The ending date of the incident.   | 
| Exabeam.incidents.fields.createdAt    | Date | The creation date of the incident.  | 
| Exabeam.incidents.fields.owner        | String | The incident owner.       | 
| Exabeam.incidents.fields.status       | String | The incident status.      | 
| Exabeam.incidents.fields.incidentType | String | The incident type.        | 
| Exabeam.incidents.fields.source       | String | The incident source.      | 
| Exabeam.incidents.fields.priority     | String | The incident priority.   | 
| Exabeam.incidents.fields.queue        | String | The incident queue.       | 
| Exabeam.incidents.fields.description  | String | The incident description. | 

#### Command Example
```!exabeam-list-incident priority=high```