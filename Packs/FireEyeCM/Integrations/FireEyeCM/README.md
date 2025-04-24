FireEye Central Management (CM Series) is the FireEye threat intelligence hub. It services the FireEye ecosystem, ensuring that FireEye products share the latest intelligence and correlate across attack vectors to detect and prevent cyber attacks
This integration was integrated and tested with version 9.0.2 of FireEye Central Management

## API Key management
This integration generates an API Key from the username and password given to be authenticated with FireEye.
The API Key is valid for 15 minutes.
The integration manages the storage of this key, and its re-generation when the key expires.

## Fetch FireEye EX Alert Emails
To fetch a FireEye EX alert email, you will need the UUID.
1. Run the ***fireeye-cm-get-alert-details** command with the alert ID. For example,
   ***!fireeye-cm-get-alert-details alert_id=542***
2. Locate the UUID in the context data and run the ***fireeye-cm-get-artifacts-by-uuid*** command with the UUID. For example: 
   ***!fireeye-cm-get-artifacts-by-uuid uuid=243a2555-a915-47a1-a947-e71049f4971c***
3. Download the email.

## Access the FireEye Alert URL
To display a proper link in the FireEye NX Alert URL field of the FireEye NX or EX Alert layout, you need to configure the hostname in the appliance settings of the FireEye application.
1. Log in to your FireEye application.
2. Navigate to **Appliance Settings > Network > Hostname**.
3. In the Hostname field, enter your URL/server/ip address.


## Configure FireEye Central Management in Cortex


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

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
| start_time | The start time of the search. This filter is optional. Syntax: start_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. Default is 1 day. | Optional | 
| end_time | The end time of the search. This filter is used with the duration filter. If the end_time is specified but not the duration, the system defaults to duration=12_hours, ending at the specified end_time. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om. | Optional | 
| callback_domain | Searches for alerts that include callbacks to the specified domain. | Optional | 
| dst_ip | The destination IPv4 address related to the malware alert. | Optional | 
| src_ip | The source IPv4 address related to the malware alert. | Optional | 
| file_name | The name of the malware file. | Optional | 
| file_type | The malware file type. | Optional | 
| info_level | The level of information to be returned. Possible values: "concise", "normal", and "extended". Possible values are: concise, normal, extended. Default is concise. | Optional | 
| malware_name | The name of the malware object. | Optional | 
| malware_type | The type of the malware object. Possible values: "domain_match", "malware_callback", "malware_object", "web_infection", "infection_match", "riskware-infection", "riskware-callback", "riskware-object". Possible values are: domain_match, malware_callback, malware_object, web_infection, infection_match, riskware-infection, riskware-callback, riskware-object. | Optional | 
| md5 | Searches for alerts that include a specific MD5 hash. | Optional | 
| recipient_email | The email address of the malware object receiver. | Optional | 
| sender_email | The email address of the malware object sender. | Optional | 
| url | Searches for a specific alert URL. | Optional | 
| limit | Maximum number of alerts to return. Default is 20. | Optional | 


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
| FireEyeCM.Alerts.sensor | String | The sensor name that the alert is associated with. | 
| FireEyeCM.Alerts.applianceId | String | The appliance ID of the alert. | 
| FireEyeCM.Alerts.sensorIp | String | The sensor IP that the alert is associated with. | 
| FireEyeCM.Alerts.ack | String | A flag indicating whether an acknowledgment is received. | 
| FireEyeCM.Alerts.src | Unknown | The source of the alert. | 
| FireEyeCM.Alerts.dst | Unknown | The destination of the alert. | 
| FireEyeCM.Alerts.explanation | Unknown | The explanation data of the alert. | 


#### Command Example
```!fireeye-cm-get-alerts```

#### Context Example
```json
{
    "FireEyeCM": {
        "Alerts": [
            {
                "ack": "no",
                "action": "notified",
                "alertUrl": "https://FireEyeCM/event_stream/events_for_bot?ev_id=35685",
                "applianceId": "test",
                "attackTime": "2021-06-10 21:52:43 +0000",
                "dst": {
                    "ip": "1.1.1.1",
                    "mac": "00:50:56:94:b8:42",
                    "port": 443
                },
                "explanation": {
                    "malwareDetected": {
                        "malware": [
                            {
                                "name": "Trojan.Malicious.SSL.Certificate.Dridex"
                            }
                        ]
                    },
                    "osChanges": []
                },
                "id": 35685,
                "malicious": "yes",
                "name": "MALWARE_CALLBACK",
                "occurred": "2021-06-10 21:52:43 +0000",
                "product": "WEB_MPS",
                "rootInfection": 34670,
                "scVersion": "1163.102",
                "sensor": "sensor",
                "sensorIp": "1.1.1.1",
                "severity": "CRIT",
                "src": {
                    "ip": "1.1.1.1",
                    "port": 8080
                },
                "uuid": "529023c0-6ddf-4933-9241-fe4ec71a788e",
                "vlan": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### FireEye Central Management Alerts:
>|id|occurred|product|name|malicious|severity|alertUrl|
>|---|---|---|---|---|---|---|
>| 35685 | 2021-06-10 21:52:43 +0000 | WEB_MPS | MALWARE_CALLBACK | yes | CRIT | https://FireEyeCM/event_stream/events_for_bot?ev_id=35685 |



### fireeye-cm-get-alert-details
***
Searches and retrieves the details of a single alert.


#### Base Command

`fireeye-cm-get-alert-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert for which to retrieve its details. | Required |
| timeout | Timeout to retrieve the artifacts. Default is 30 seconds. | Optional |


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
| FireEyeCM.Alerts.sensor | String | The sensor name that the alert is associated with. | 
| FireEyeCM.Alerts.applianceId | String | The appliance ID of the alert. | 
| FireEyeCM.Alerts.sensorIp | String | The sensor IP that the alert is associated with. | 
| FireEyeCM.Alerts.ack | String | A flag indicating whether an acknowledgment is received. | 
| FireEyeCM.Alerts.src | Unknown | The source of the alert. | 
| FireEyeCM.Alerts.dst | Unknown | The destination of the alert. | 
| FireEyeCM.Alerts.explanation | Unknown | The explanation data of the alert. | 


#### Command Example
```!fireeye-cm-get-alert-details alert_id=35685```

#### Context Example
```json
{
    "FireEyeCM": {
        "Alerts": {
            "ack": "no",
            "action": "notified",
            "alertUrl": "https://FireEyeCM/event_stream/events_for_bot?ev_id=35685",
            "applianceId": "test",
            "attackTime": "2021-06-10 21:52:43 +0000",
            "dst": {
                "ip": "1.1.1.1",
                "mac": "00:50:56:94:b8:42",
                "port": 443
            },
            "explanation": {
                "malwareDetected": {
                    "malware": [
                        {
                            "name": "Trojan.Malicious.SSL.Certificate.Dridex"
                        }
                    ]
                },
                "osChanges": []
            },
            "id": 35685,
            "malicious": "yes",
            "name": "MALWARE_CALLBACK",
            "occurred": "2021-06-10 21:52:43 +0000",
            "product": "WEB_MPS",
            "rootInfection": 34670,
            "scVersion": "1163.102",
            "sensor": "sensor",
            "sensorIp": "1.1.1.1",
            "severity": "CRIT",
            "src": {
                "ip": "1.1.1.1",
                "port": 8080
            },
            "uuid": "529023c0-6ddf-4933-9241-fe4ec71a788e",
            "vlan": 0
        }
    }
}
```

#### Human Readable Output

>### FireEye Central Management Alerts:
>|id|occurred|product|name|malicious|action|src|dst|severity|alertUrl|
>|---|---|---|---|---|---|---|---|---|---|
>| 35685 | 2021-06-10 21:52:43 +0000 | WEB_MPS | MALWARE_CALLBACK | yes | notified | ip: 34.252.247.142<br/>port: 51270 | mac: 00:50:56:94:b8:42<br/>port: 443<br/>ip: 192.168.1.202 | CRIT | https://FireEyeCM/event_stream/events_for_bot?ev_id=35685 |


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
```!fireeye-cm-alert-acknowledge uuid=529023c0-6ddf-4933-9241-fe4ec71a788e```

#### Human Readable Output

>Alert 529023c0-6ddf-4933-9241-fe4ec71a788e was acknowledged successfully.

### fireeye-cm-get-artifacts-by-uuid
***
Downloads malware artifacts data for the specified UUID as a zip file.


#### Base Command

`fireeye-cm-get-artifacts-by-uuid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The universally unique identifier (UUID) for the alert. | Required | 
| timeout | Timeout to retrieve the artifacts. Default is 120 seconds. | Optional | 


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
```!fireeye-cm-get-artifacts-by-uuid uuid=b38b83a0-4b96-408c-999f-4e97a5099f61```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "400@2c246757-e02c-458a-8620-dbc236283fb8",
        "Extension": "zip",
        "Info": "application/zip",
        "Name": "artifacts_b38b83a0-4b96-408c-999f-4e97a5099f61.zip",
        "Size": 5501,
        "Type": "Zip archive data, at least v2.0 to extract"
    }
}
```

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
```!fireeye-cm-get-artifacts-metadata-by-uuid uuid=b38b83a0-4b96-408c-999f-4e97a5099f61```

#### Context Example
```json
{
    "FireEyeCM": {
        "Alerts": {
            "artifactsInfoList": [
                {
                    "artifactName": "34.252.247.142-192.168.1.202-1620538334558058-33354739.txt.gz",
                    "artifactSize": "1641",
                    "artifactType": "l7_context_file"
                },
                {
                    "artifactName": "192.168.1.202-34.252.247.142-1620538334557811-33354739-cs.pcap",
                    "artifactSize": "3645",
                    "artifactType": "bott_communication_capture"
                }
            ],
            "uuid": "b38b83a0-4b96-408c-999f-4e97a5099f61"
        }
    }
}
```

#### Human Readable Output

>### FireEye Central Management b38b83a0-4b96-408c-999f-4e97a5099f61 Artifact metadata:
>|artifactName|artifactSize|artifactType|
>|---|---|---|
>| 34.252.247.142-192.168.1.202-1620538334558058-33354739.txt.gz | 1641 | l7_context_file |
>| 192.168.1.202-34.252.247.142-1620538334557811-33354739-cs.pcap | 3645 | bott_communication_capture |


### fireeye-cm-get-events
***
Retrieves information about existing IPS NX events. An IPS enabled appliance is a prerequisite to be able to retrieve IPS event data.


#### Base Command

`fireeye-cm-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| duration | The time interval in which to search. This filter is used with the end_time filter. If the duration is not specified, the system defaults to duration=12_hours, end_time=current_time. Possible values are: 1_hour, 2_hours, 6_hours, 12_hours, 24_hours, 48_hours. | Optional | 
| end_time | The end time of the search. This filter is used with the duration filter. If the end_time is specified but not the duration, the system defaults to duration=12_hours, ending at the specified end_time. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om. | Optional | 
| mvx_correlated_only | Specifies whether to include all IPS events or MVX-correlated events only. Possible values: "true" and "false". Possible values are: false, true. Default is false. | Optional | 
| limit | Maximum number of events to return. Default is 20. | Optional | 


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
```!fireeye-cm-get-events duration="48_hours" end_time="2021-05-14T01:08:04.000-02:00" mvx_correlated_only="true"```

#### Human Readable Output

>No events in the given timeframe were found.

### fireeye-cm-get-quarantined-emails
***
Searches and retrieves quarantined emails.


#### Base Command

`fireeye-cm-get-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Specifies the start time of the search. This filter is optional. Syntax: start_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. Default is 1 day. | Optional | 
| end_time | Specifies the end time of the search. Default is now. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. | Optional | 
| from | The sender email. | Optional | 
| subject | The email subject. Must be URL encoded. | Optional | 
| appliance_id | The appliance ID. | Optional | 
| limit | Number of emails to return. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeCM.QuarantinedEmail.appliance_id | string | The appliance ID associated with the quarantined email. | 
| FireEyeCM.QuarantinedEmail.completed_at | string | The time the email has been quarantined. | 
| FireEyeCM.QuarantinedEmail.email_uuid | string | The quarantined email UUID. | 
| FireEyeCM.QuarantinedEmail.from | string | The quarantined email sender. | 
| FireEyeCM.QuarantinedEmail.message_id | string | The quarantined email message ID. | 
| FireEyeCM.QuarantinedEmail.quarantine_path | string | The quarantined email path. | 
| FireEyeCM.QuarantinedEmail.The quarantined email queue id. | string | The quarantined email queue ID. | 
| FireEyeCM.QuarantinedEmail.subject | string | The quarantined email subject. | 


#### Command Example
```!fireeye-cm-get-quarantined-emails start_time="1 month" limit=4```

#### Context Example
```json
{
    "FireEyeCM": {
        "QuarantinedEmail": [
            {
                "appliance_id": "test",
                "completed_at": "2021-05-24T09:04:03",
                "email_uuid": "d7738eb0-7fe7-4b5d-8fcb-2b053ef57e13",
                "from": "test@malicious.net",
                "message_id": "queue-id-test@no-message-id",
                "quarantine_path": "/data/email-analysis/quarantine2/2021-05-24/09/test",
                "queue_id": "4FpWV31wpbzTgF9",
                "subject": "test"
            },
            {
                "appliance_id": "test",
                "completed_at": "2021-05-24T16:01:16",
                "email_uuid": "9e73ca23-b935-47c2-8d2a-fe1a10071db2",
                "from": "test@malicious.net",
                "message_id": "queue-id-test@no-message-id",
                "quarantine_path": "/data/email-analysis/quarantine2/2021-05-24/16/test",
                "queue_id": "test",
                "subject": "test"
            },
            {
                "appliance_id": "test",
                "completed_at": "2021-05-24T16:01:16",
                "email_uuid": "e7b52446-555d-40d0-b8ad-e8f1f2a7ab7a",
                "from": "test@malicious.net",
                "message_id": "queue-id-test@no-message-id",
                "quarantine_path": "/data/email-analysis/quarantine2/2021-05-24/16/test",
                "queue_id": "test",
                "subject": "test"
            },
            {
                "appliance_id": "test",
                "completed_at": "2021-05-24T16:01:16",
                "email_uuid": "ebb991b5-06ef-44f4-b44d-e1daef67ce70",
                "from": "test@malicious.net",
                "message_id": "queue-id-test@no-message-id",
                "quarantine_path": "/data/email-analysis/quarantine2/2021-05-24/16/test",
                "queue_id": "test",
                "subject": "test"
            }
        ]
    }
}
```

#### Human Readable Output

>### FireEye Central Management Quarantined emails:
>|email_uuid|from|subject|message_id|completed_at|
>|---|---|---|---|---|
>| d7738eb0-7fe7-4b5d-8fcb-2b053ef57e13 | test@malicious.net | test | queue-id-test@no-message-id | 2021-05-24T09:04:03 |
>| 9e73ca23-b935-47c2-8d2a-fe1a10071db2 | test@malicious.net | test | queue-id-test@no-message-id | 2021-05-24T16:01:16 |
>| e7b52446-555d-40d0-b8ad-e8f1f2a7ab7a | test@malicious.net | test | queue-id-test@no-message-id | 2021-05-24T16:01:16 |
>| ebb991b5-06ef-44f4-b44d-e1daef67ce70 | test@malicious.net | test | queue-id-test@no-message-id | 2021-05-24T16:01:16 |


### fireeye-cm-release-quarantined-emails
***
Releases and deletes quarantined emails. This is not available when Email Security is in Drop mode.


#### Base Command

`fireeye-cm-release-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_ids | A comma-separated list of quarantined email queue IDs. Supports up to 100 IDs. | Required | 
| sensor_name | The sensor display name. | Required | 


#### Context Output

There is no context output for this command.



### fireeye-cm-delete-quarantined-emails
***
Deletes quarantined emails. This is not available when Email Security is in Drop mode.


#### Base Command

`fireeye-cm-delete-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_ids | A comma-separated list of quarantined email queue IDs. Supports up to 100 IDs. | Required | 
| sensor_name | The sensor display name. | Required | 


#### Context Output

There is no context output for this command.



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
```!fireeye-cm-download-quarantined-emails sensor_name=FireEyeEX queue_id=test```

#### Context Example
```json
{
    "File": {
        "EntryID": "420@2c246757-e02c-458a-8620-dbc236283fb8",
        "Extension": "eml",
        "Info": "message/rfc822",
        "MD5": "634996e695399dfc43488047c8316eaf",
        "Name": "quarantined_email_4FpWV31wpbzTgF9.eml",
        "SHA1": "5e6f89930c81da3f562eb630b4f881315bb56103",
        "SHA256": "218f9c5975dc12e3e3857474669cda62df063051a46213042f5b404ae8bf138f",
        "SHA512": "a7c19471fb4f2b752024246c28a37127ea7475148c04ace743392334d0ecc4762baf30b892d6a24b335e1065b254166f905fc46cc3ba5dba89e757bb7023a211",
        "SSDeep": "6:tnWrw+bcnWd4jXQ93f9FfZPny8ZijRSF1OZKi1rzfSY4SXfT8oERf:tnWrwWcnWd4M9fZvy8SUF184MfPE5",
        "Size": 269,
        "Type": "RFC 822 mail text, ASCII text"
    }
}
```

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
| start_time | The start time of the search. This filter is optional. Syntax: start_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. Default is 1 week. | Optional | 
| end_time | Specifies the end time of the search. Default is now. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. | Optional | 
| limit | The maximum number of items covered by each report. This option is required only for IPS TopN reports. Default is 100. | Optional | 
| interface | The internet interface to one of the values. This option is required only for IPS reports. Possible values are: A, B, AB. | Optional | 
| alert_id | Alert ID. This argument is only relevant when retrieving a report of type alertDetailsReport. | Optional | 
| infection_id | Infection ID. This argument is only relevant when retrieving a report of type alertDetailsReport with conjunction to the infection_type argument. | Optional | 
| infection_type | Infection type. Possible values: "malware-object", "malware-callback", "infection-match", "domain-match", "web-infection". This argument is only relevant when retrieving a report of type alertDetailsReport with conjunction to the infection_id argument. Possible values are: malware-object, malware-callback, infection-match, domain-match, web-infection. | Optional | 
| timeout | Timeout to retrieve the reports. Default is 120 seconds. | Optional | 


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


## Known Limitations
Clicking the **Test** button of the **Integration instance settings** window verifies that the instance configuration is correct.
Due to a known limitation, clicking the **Test** button several times in quick succession may result in an "Unauthorized" error, even after a successful result was initially returned. It is enough to receive one success message to verify that the configuration is correct. "Unauthorized" error messages received from repeated clicking of the instance configuration **Test** button do not affect the validity of the instance if the initial response was successful.