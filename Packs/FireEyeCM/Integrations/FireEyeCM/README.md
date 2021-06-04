FireEye Central Management (CM Series) is the FireEye threat intelligence hub. It services the FireEye ecosystem, ensuring that FireEye products share the latest intelligence and correlate across attack vectors to detect and prevent cyber attacks
This integration was integrated and tested with version xx of FireEye Central Management
## Configure FireEye Central Management on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FireEye Central Management.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Your server URL | True |
    | Username | True |
    | Fetch incidents | False |
    | Max incidents to fetch | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) | False |
    | Incident type | False |
    | Info level for fetched alerts | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fireeye-cm-get-alerts
***
Searches and retrieves FireEye CM alerts based on several filters.


#### Base Command

`fireeye-cm-get-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID number of the alert to retrieve. | Optional | 
| duration | The time interval to search. This filter is used with either the start_time or end_time filter. If duration, start time, and end time are not specified, the system defaults to duration=12_hours, end_time=current_time. If only the duration is specified, the end_time defaults to the current_time. Possible values are: 1_hour, 2_hours, 6_hours, 12_hours, 24_hours, 48_hours. | Optional | 
| start_time | The start time of the search. This filter is optional. Default is last day. Syntax: start_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. | Optional | 
| end_time | The end time of the search. This filter is used with the duration filter. If the end_time is specified but not the duration, the system defaults to duration=12_hours, ending at the specified end_time. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om. | Optional | 
| callback_domain | Searches for alerts that include callbacks to the specified domain. | Optional | 
| dst_ip | The destination IPv4 address related to the malware alert. | Optional | 
| src_ip | The source IPv4 address related to the malware alert. | Optional | 
| file_name | The name of the malware file. | Optional | 
| file_type | The malware file type. | Optional | 
| info_level | Specifies the level of information to be returned. The default is concise. Possible values are: concise, normal, extended. Default is concise. | Optional | 
| malware_name | The name of the malware object. | Optional | 
| malware_type | The type of the malware object. Possible values are: domain_match, malware_callback, malware_object, web_infection, infection_match, riskware-infection, riskware-callback, riskware-object. | Optional | 
| md5 | Searches for alerts that include a specific MD5 hash. | Optional | 
| recipient_email | The email address of the malware object receiver. | Optional | 
| sender_email | The email address of the malware object sender. | Optional | 
| url | Searches for a specific alert URL. | Optional | 
| limit | Maximum number of alerts to return. Default is 20. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeCM.Alerts.id | String | The ID of the alert. | 
| FireEyeCM.Alerts.uuid | String | The UUID of the alert. | 
| FireEyeCM.Alerts.occurred | String | The time when the alert occurred. | 
| FireEyeCM.Alerts.product | String | The product name of the alert. | 
| FireEyeCM.Alerts.rootInfection | String | The ID of the infection associated with the malware alert. | 
| FireEyeCM.Alerts.name | String | The link to the infection associated with the malware alert. | 
| FireEyeCM.Alerts.vlan | String | The virtual LAN \(VLAN\) of the alert. | 
| FireEyeCM.Alerts.malicious | String | A flag indicating whether the alert is malicious. | 
| FireEyeCM.Alerts.severity | String | The severity of the alert. | 
| FireEyeCM.Alerts.sensor | String | The sensor name which the alert associated with. | 
| FireEyeCM.Alerts.applianceId | String | The appliance ID of the alert. | 
| FireEyeCM.Alerts.sensorIp | String | The sensor IP which the alert associated with. | 
| FireEyeCM.Alerts.ack | String | A flag indicating whether an acknowledgment is received. | 
| FireEyeCM.Alerts.src | Unknown | The source of the alert. | 
| FireEyeCM.Alerts.dst | Unknown | The destination of the alert. | 
| FireEyeCM.Alerts.explanation | Unknown | The explanation data of the alert. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-cm-get-alert-details
***
Searches and retrieves the details of a single alert.


#### Base Command

`fireeye-cm-get-alert-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID number of the alert to retrieve its details. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeCM.Alerts.id | String | The ID of the alert. | 
| FireEyeCM.Alerts.uuid | String | The UUID of the alert. | 
| FireEyeCM.Alerts.occurred | String | The time when the alert occurred. | 
| FireEyeCM.Alerts.product | String | The product name of the alert. | 
| FireEyeCM.Alerts.rootInfection | String | The ID of the infection associated with the malware alert. | 
| FireEyeCM.Alerts.name | String | The link to the infection associated with the malware alert. | 
| FireEyeCM.Alerts.vlan | String | The virtual LAN \(VLAN\) of the alert. | 
| FireEyeCM.Alerts.malicious | String | A flag indicating whether the alert is malicious. | 
| FireEyeCM.Alerts.severity | String | The severity of the alert. | 
| FireEyeCM.Alerts.sensor | String | The sensor name which the alert associated with. | 
| FireEyeCM.Alerts.applianceId | String | The appliance ID of the alert. | 
| FireEyeCM.Alerts.sensorIp | String | The sensor IP which the alert associated with. | 
| FireEyeCM.Alerts.ack | String | A flag indicating whether an acknowledgment is received. | 
| FireEyeCM.Alerts.src | Unknown | The source of the alert. | 
| FireEyeCM.Alerts.dst | Unknown | The destination of the alert. | 
| FireEyeCM.Alerts.explanation | Unknown | The explanation data of the alert. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-cm-alert-acknowledge
***
Confirms that the alert has been reviewed.


#### Base Command

`fireeye-cm-alert-acknowledge`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The universally unique identifier (UUID) for the alert. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fireeye-cm-get-artifacts-by-uuid
***
Downloads malware artifacts data for the specified UUID as a zip file.


#### Base Command

`fireeye-cm-get-artifacts-by-uuid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The universally unique identifier (UUID) for the alert. | Required | 
| timeout | Timeout to retrieve the artifacts. Default is 120. Default is 120. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | string | The EntryID of the artifact file. | 
| InfoFile.Extension | string | The extension of the artifact file. | 
| InfoFile.Name | string | The name of the artifact file. | 
| InfoFile.Info | string | The info of the artifact file. | 
| InfoFile.Size | number | The size of the artifact file. | 
| InfoFile.Type | string | The type of the artifact file. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-cm-get-artifacts-metadata-by-uuid
***
Gets artifacts metadata for the specified UUID.


#### Base Command

`fireeye-cm-get-artifacts-metadata-by-uuid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The universally unique identifier (UUID) for the alert. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeCM.Alerts.uuid | string | Universally unique ID \(UUID\) of the alert. | 
| FireEyeCM.Alerts.artifactsInfoList.artifactType | string | The artifact type. | 
| FireEyeCM.Alerts.artifactsInfoList.artifactName | string | The artifact name. | 
| FireEyeCM.Alerts.artifactsInfoList.artifactSize | string | The zipped artifact size in bytes. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-cm-get-events
***
Retrieves information about existing IPS NX events. An IPS enabled appliance is a prerequisite to be able to retrieve IPS event data.


#### Base Command

`fireeye-cm-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| duration | Specifies the time interval to search. This filter is used with the end_time filter. If the duration is not specified, the system defaults to duration=12_hours, end_time=current_time. Possible values are: 1_hour, 2_hours, 6_hours, 12_hours, 24_hours, 48_hours. | Optional | 
| end_time | Specifies the end time of the search. This filter is used with the duration filter. If the end_time is specified but not the duration, the system defaults to duration=12_hours, ending at the specified end_time. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om. | Optional | 
| mvx_correlated_only | Specifies whether to include all IPS events or MVX-correlated events only. Default is false. Possible values are: false, true. Default is false. | Optional | 
| limit | Maximum number of events to return. Default is 20. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeCM.Events.eventId | Number | The ID of the event. | 
| FireEyeCM.Events.occurred | string | The date and time when the event occurred. | 
| FireEyeCM.Events.srcIp | string | The IP address of the victim. | 
| FireEyeCM.Events.srcPort | Number | The port address of the victim. | 
| FireEyeCM.Events.dstIp | string | The IP address of the attacker. | 
| FireEyeCM.Events.dstPort | Number | The port address of the attacker. | 
| FireEyeCM.Events.vlan | Number | The virtual LAN \(VLAN\) of the event. | 
| FireEyeCM.Events.signatureMatchCnt | String | The date and time when the event occurred. | 
| FireEyeCM.Events.signatureId | String | The ID of the event. | 
| FireEyeCM.Events.signatureRev | String | The date and time when the event occurred. | 
| FireEyeCM.Events.severity | String | The ID of the event. | 
| FireEyeCM.Events.vmVerified | String | The date and time when the event occurred. | 
| FireEyeCM.Events.srcMac | String | The MAC address of the source machine. | 
| FireEyeCM.Events.dstMac | String | The MAC address of the destination machine. | 
| FireEyeCM.Events.ruleName | String | The rule name for the event. | 
| FireEyeCM.Events.sensorId | String | The sensor ID of the FireEye machine. | 
| FireEyeCM.Events.cveId | String | The CVE ID found in the event. | 
| FireEyeCM.Events.actionTaken | String | The IPS blocking action taken on the event. | 
| FireEyeCM.Events.attackMode | String | The attack mode mentioned in the event. | 
| FireEyeCM.Events.interfaceId | Number | The interface ID of the event. | 
| FireEyeCM.Events.protocol | Number | The protocol used in the event. | 
| FireEyeCM.Events.incidentId | Number | The incident ID of the event on FireEye. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-cm-get-quarantined-emails
***
Searches and retrieves quarantined emails.


#### Base Command

`fireeye-cm-get-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Specifies the start time of the search. This filter is optional. Default is last day. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. Default is 1 day. | Optional | 
| end_time | Specifies the end time of the search. Default is now. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. | Optional | 
| from | The sender email. | Optional | 
| subject | The email subject. Must be URL encoded. | Optional | 
| appliance_id | The appliance ID. | Optional | 
| limit | Number of emails to return. Default is 20. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeCM.QuarantinedEmail.appliance_id | string | The appliance ID associated with the quarantined email. | 
| FireEyeCM.QuarantinedEmail.completed_at | string | The time the email has been quarantined. | 
| FireEyeCM.QuarantinedEmail.email_uuid | string | The quarantined email UUID. | 
| FireEyeCM.QuarantinedEmail.from | string | The quarantined email sender. | 
| FireEyeCM.QuarantinedEmail.message_id | string | The quarantined email message id. | 
| FireEyeCM.QuarantinedEmail.quarantine_path | string | The quarantined email path. | 
| FireEyeCM.QuarantinedEmail.The quarantined email queue id. | string | The quarantined email queue id. | 
| FireEyeCM.QuarantinedEmail.subject | string | The quarantined email subject. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-cm-release-quarantined-emails
***
Releases and deletes quarantined emails. This is not available when Email Security is in Drop mode.


#### Base Command

`fireeye-cm-release-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_ids | The quarantined emails queue IDs. Supports up to 100 IDs. | Required | 
| sensor_name | The sensor display name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fireeye-cm-delete-quarantined-emails
***
Deletes quarantined emails. This is not available when Email Security is in Drop mode.


#### Base Command

`fireeye-cm-delete-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_ids | The quarantined emails queue IDs. Supports up to 100 IDs. | Required | 
| sensor_name | The sensor display name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fireeye-cm-download-quarantined-emails
***
Download quarantined emails.


#### Base Command

`fireeye-cm-download-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_id | The quarantined emails queue ID. | Required | 
| sensor_name | The sensor display name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The name of the email. | 
| File.MD5 | String | The MD5 hash of the email. | 
| File.SHA1 | String | The SHA1 hash of the email. | 
| File.SHA256 | String | The SHA256 hash of the email. | 
| File.Type | String | The file type. | 
| File.Size | Number | The size of the email in bytes. | 
| File.SSDeep | String | The SSDeep hash of the email. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-cm-get-reports
***
Returns reports on selected alerts.


#### Base Command

`fireeye-cm-get-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_type | The report type. Requests for ipsTopNAttack, ipsTopNAttacker, ipsTopNVictim, or ipsTopNMvxVerified reports must be used with the limit parameter set to either 25, 50, 75, or 100. You must have an Intrusion Prevention System (IPS)-enabled appliance to be able to generate the IPS reports. Possible values are: empsEmailAVReport, empsEmailActivity, empsEmailExecutiveSummary, empsEmailHourlyStat, mpsCallBackServer, mpsExecutiveSummary, mpsInfectedHostsTrend, mpsMalwareActivity, mpsWebAVReport, ipsExecutiveSummary, ipsTopNAttack, ipsTopNAttacker, ipsTopNVictim, ipsTopNMvxVerified, alertDetailsReport. | Required | 
| start_time | Specifies the start time of the search. This filter is optional. Default is last week. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. Default is 1 week. | Optional | 
| end_time | Specifies the end time of the search. Default is now. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. | Optional | 
| limit | Default is 100. This option is required only for IPS TopN reports. The limit option sets the maximum number (N) of items covered by each report. Default is 100. | Optional | 
| interface | This option is required only for IPS reports. The interface option sets ihe internet interface to one of the values. Possible values are: A, B, AB. | Optional | 
| alert_id | Alert ID. This argument is only relevant when retrieving a report of type alertDetailsReport. | Optional | 
| infection_id | Infection ID. This argument is only relevant when retrieving a report of type alertDetailsReport with conjunction to the infection_type argument. | Optional | 
| infection_type | Infection Type. This argument is only relevant when retrieving a report of type alertDetailsReport with conjunction to the infection_id argument. Possible values are: malware-object, malware-callback, infection-match, domain-match, web-infection. | Optional | 
| timeout | Timeout to retrieve the reports. Default is 120. Default is 120. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryID | string | The EntryID of the artifact file. | 
| InfoFile.Extension | string | The extension of the artifact file. | 
| InfoFile.Name | string | The name of the artifact file. | 
| InfoFile.Info | string | The info of the artifact file. | 
| InfoFile.Size | number | The size of the artifact file. | 
| InfoFile.Type | string | The type of the artifact file. | 


#### Command Example
``` ```

#### Human Readable Output


