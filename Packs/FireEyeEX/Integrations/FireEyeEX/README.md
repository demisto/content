FireEye Email Security (EX) series protects against breaches caused by advanced email attacks.
This integration was integrated and tested with version 9.0.2.929543 of FireEye Email Security.

## API Key management
This integration generates an API Key from the username and password given to be authenticated with FireEye.
The API Key is valid for 15 minutes.
The integration manages the storage of this key, and its re-generation when the key expires.

## Fetch FireEye EX Alert Emails
To fetch a FireEye EX alert email, you will need the UUID.
1. Run the ***fireeye-ex-get-alert-details** command with the alert ID. For example,
   ***!fireeye-ex-get-alert-details alert_id=542***
2. Locate the UUID in the context data and run the ***fireeye-ex-get-artifacts-by-uuid*** command with the UUID. For example: 
   ***!fireeye-ex-get-artifacts-by-uuid uuid=243a2555-a915-47a1-a947-e71049f4971c***
3. Download the email.

## Access the FireEye Alert URL
To display a proper link in the FireEye NX Alert URL field of the FireEye EX Alert layout, you need to configure the hostname in the appliance settings of the FireEye application.
1. Log in to your FireEye application.
3. In the Hostname field, enter your URL/server/ip address.

## Configure FireEye Email Security in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.

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
### fireeye-ex-get-alerts
***
Searches and retrieves FireEye EX alerts based on several filters.


#### Base Command

`fireeye-ex-get-alerts`
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
| info_level | The level of information to be returned. Possible values are: concise, normal, extended. Default is concise. | Optional | 
| malware_name | The name of the malware object. | Optional | 
| malware_type | The type of the malware object. Possible values are: domain_match, malware_callback, malware_object, web_infection, infection_match, riskware-infection, riskware-callback, riskware-object. | Optional | 
| md5 | Searches for alerts that include a specific MD5 hash. | Optional | 
| recipient_email | The email address of the malware object receiver. | Optional | 
| sender_email | The email address of the malware object sender. | Optional | 
| url | Searches for a specific alert URL. | Optional | 
| limit | Maximum number of alerts to return. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.Alerts.id | String | The ID of the alert. | 
| FireEyeEX.Alerts.uuid | String | The UUID of the alert. | 
| FireEyeEX.Alerts.occurred | String | The time when the alert occurred. | 
| FireEyeEX.Alerts.product | String | The product name of the alert. | 
| FireEyeEX.Alerts.rootInfection | String | The ID of the infection associated with the malware alert. | 
| FireEyeEX.Alerts.name | String | The link to the infection associated with the malware alert. | 
| FireEyeEX.Alerts.vlan | String | The virtual LAN \(VLAN\) of the alert. | 
| FireEyeEX.Alerts.malicious | String | A flag indicating whether the alert is malicious. | 
| FireEyeEX.Alerts.severity | String | The severity of the alert. | 
| FireEyeEX.Alerts.sensor | String | The sensor name that the alert is associated with. | 
| FireEyeEX.Alerts.applianceId | String | The appliance ID of the alert. | 
| FireEyeEX.Alerts.sensorIp | String | The sensor IP that the alert is associated with. | 
| FireEyeEX.Alerts.ack | String | A flag indicating whether an acknowledgment is received. | 
| FireEyeEX.Alerts.src | Unknown | The source of the alert. | 
| FireEyeEX.Alerts.dst | Unknown | The destination of the alert. | 
| FireEyeEX.Alerts.explanation | Unknown | The explanation data of the alert. | 


#### Command Example
```!fireeye-ex-get-alerts start_time="2 month" sender_email="test@malicious.net" limit=4```

#### Context Example
```json
{
    "FireEyeEX": {
        "Alerts": [
            {
                "ack": "no",
                "action": "notified",
                "alertUrl": "https://FireEyeEX/emps/eanalysis?e_id=9&type=url",
                "applianceId": "86A8D8FA2D11",
                "attackTime": "2021-02-14 09:42:43 +0000",
                "dst": {
                    "smtpTo": "test@actualdomain.org"
                },
                "explanation": {
                    "malwareDetected": {
                        "malware": [
                            {
                                "md5Sum": "271c1bcd28d01c6863fdb5b5c5d94e73",
                                "name": "FETestEvent",
                                "sha256": "abebb5862eea61a3d0a1c75bf5a2e2abcd6c4ee6a6ad086e1d518445594970fc"
                            }
                        ]
                    },
                    "osChanges": []
                },
                "id": 1,
                "malicious": "yes",
                "name": "MALWARE_OBJECT",
                "occurred": "2021-02-14 09:42:47 +0000",
                "product": "EMAIL_MPS",
                "scVersion": "1115.212",
                "severity": "MAJR",
                "smtpMessage": {
                    "subject": "test"
                },
                "src": {
                    "smtpMailFrom": "test@malicious.net"
                },
                "uuid": "1174ddc9-f7cc-4c38-a08c-42fcc5c04d31",
                "vlan": 0
            },
            {
                "ack": "no",
                "action": "notified",
                "alertUrl": "https://FireEyeEX/emps/eanalysis?e_id=10&type=url",
                "applianceId": "86A8D8FA2D11",
                "attackTime": "2021-02-14 09:43:51 +0000",
                "dst": {
                    "smtpTo": "test@actualdomain.org"
                },
                "explanation": {
                    "malwareDetected": {
                        "malware": [
                            {
                                "md5Sum": "6efaa05d0d98711416f7d902639155fb",
                                "name": "FETestEvent",
                                "sha256": "340d367ebe68ad833ea055cea7678463a896d03eae86f7816cc0c836b9508fa8"
                            }
                        ]
                    },
                    "osChanges": []
                },
                "id": 2,
                "malicious": "yes",
                "name": "MALWARE_OBJECT",
                "occurred": "2021-02-14 09:43:55 +0000",
                "product": "EMAIL_MPS",
                "scVersion": "1115.212",
                "severity": "MAJR",
                "smtpMessage": {
                    "subject": "test"
                },
                "src": {
                    "smtpMailFrom": "test@malicious.net"
                },
                "uuid": "e7656103-4faa-4853-b9a4-dbc615302aad",
                "vlan": 0
            },
            {
                "ack": "no",
                "action": "notified",
                "alertUrl": "https://FireEyeEX/emps/eanalysis?e_id=12&type=url",
                "applianceId": "86A8D8FA2D11",
                "attackTime": "2021-02-14 09:45:55 +0000",
                "dst": {
                    "smtpTo": "test@actualdomain.org"
                },
                "explanation": {
                    "malwareDetected": {
                        "malware": [
                            {
                                "md5Sum": "a705075df02f217e8bfc9ac5ec2ffee2",
                                "name": "Malicious.LIVE.DTI.URL",
                                "sha256": "d1eeadbb4e3d1c57af5a069a0886aa2b4f71484721aafe5c90708b66b8d0090a"
                            }
                        ]
                    },
                    "osChanges": []
                },
                "id": 3,
                "malicious": "yes",
                "name": "MALWARE_OBJECT",
                "occurred": "2021-02-14 09:45:58 +0000",
                "product": "EMAIL_MPS",
                "scVersion": "1115.212",
                "severity": "MAJR",
                "smtpMessage": {
                    "subject": "test"
                },
                "src": {
                    "smtpMailFrom": "test@malicious.net"
                },
                "uuid": "da0a1ee3-da28-46fa-9e5d-6663a76babba",
                "vlan": 0
            },
            {
                "ack": "no",
                "action": "notified",
                "alertUrl": "https://FireEyeEX/emps/eanalysis?e_id=16&type=url",
                "applianceId": "86A8D8FA2D11",
                "attackTime": "2021-02-14 09:53:30 +0000",
                "dst": {
                    "smtpTo": "test@actualdomain.org"
                },
                "explanation": {
                    "malwareDetected": {
                        "malware": [
                            {
                                "md5Sum": "2a0bea4c95837d5e6c62eb1e7faa4cc4",
                                "name": "Phish.LIVE.DTI.URL",
                                "sha256": "56805163764d9eab8b7311844fa0df3c4c32535042794b1c9a24579fb7836f29"
                            }
                        ]
                    },
                    "osChanges": []
                },
                "id": 4,
                "malicious": "yes",
                "name": "MALWARE_OBJECT",
                "occurred": "2021-02-14 09:53:33 +0000",
                "product": "EMAIL_MPS",
                "scVersion": "1115.212",
                "severity": "MAJR",
                "smtpMessage": {
                    "subject": "test"
                },
                "src": {
                    "smtpMailFrom": "test@malicious.net"
                },
                "uuid": "058ed867-b131-4acf-8b14-884146329a7f",
                "vlan": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### FireEye Email Security Alerts:
>|id|occurred|product|name|malicious|severity|alertUrl|
>|---|---|---|---|---|---|---|
>| 1 | 2021-02-14 09:42:47 +0000 | EMAIL_MPS | MALWARE_OBJECT | yes | MAJR | https://FireEyeEX/emps/eanalysis?e_id=9&type=url |
>| 2 | 2021-02-14 09:43:55 +0000 | EMAIL_MPS | MALWARE_OBJECT | yes | MAJR | https://FireEyeEX/emps/eanalysis?e_id=10&type=url |
>| 3 | 2021-02-14 09:45:58 +0000 | EMAIL_MPS | MALWARE_OBJECT | yes | MAJR | https://FireEyeEX/emps/eanalysis?e_id=12&type=url |
>| 4 | 2021-02-14 09:53:33 +0000 | EMAIL_MPS | MALWARE_OBJECT | yes | MAJR | https://FireEyeEX/emps/eanalysis?e_id=16&type=url |


### fireeye-ex-get-alert-details
***
Searches and retrieves the details of a single alert.


#### Base Command

`fireeye-ex-get-alert-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert for which to retrieve its details. | Required | 
| timeout | Timeout to retrieve the alert details. Default is 30 seconds. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.Alerts.id | String | The ID of the alert. | 
| FireEyeEX.Alerts.uuid | String | The UUID of the alert. | 
| FireEyeEX.Alerts.occurred | String | The time when the alert occurred. | 
| FireEyeEX.Alerts.product | String | The product name of the alert. | 
| FireEyeEX.Alerts.rootInfection | String | The ID of the infection associated with the malware alert. | 
| FireEyeEX.Alerts.name | String | The link to the infection associated with the malware alert. | 
| FireEyeEX.Alerts.vlan | String | The virtual LAN \(VLAN\) of the alert. | 
| FireEyeEX.Alerts.malicious | String | A flag indicating whether the alert is malicious. | 
| FireEyeEX.Alerts.severity | String | The severity of the alert. | 
| FireEyeEX.Alerts.sensor | String | The sensor name that the alert is associated with. | 
| FireEyeEX.Alerts.applianceId | String | The appliance ID of the alert. | 
| FireEyeEX.Alerts.sensorIp | String | The sensor IP that the alert is associated with. | 
| FireEyeEX.Alerts.ack | String | A flag indicating whether an acknowledgment is received. | 
| FireEyeEX.Alerts.src | Unknown | The source of the alert. | 
| FireEyeEX.Alerts.dst | Unknown | The destination of the alert. | 
| FireEyeEX.Alerts.explanation | Unknown | The explanation data of the alert. | 


#### Command Example
```!fireeye-ex-get-alert-details alert_id=3```

#### Context Example
```json
{
    "FireEyeEX": {
        "Alerts": {
            "ack": "no",
            "action": "notified",
            "alertUrl": "https://FireEyeEX/emps/eanalysis?e_id=12&type=url",
            "applianceId": "86A8D8FA2D11",
            "attackTime": "2021-02-14 09:45:55 +0000",
            "dst": {
                "smtpTo": "test@actualdomain.org"
            },
            "explanation": {
                "malwareDetected": {
                    "malware": [
                        {
                            "md5Sum": "a705075df02f217e8bfc9ac5ec2ffee2",
                            "name": "Malicious.LIVE.DTI.URL",
                            "sha256": "d1eeadbb4e3d1c57af5a069a0886aa2b4f71484721aafe5c90708b66b8d0090a"
                        }
                    ]
                },
                "osChanges": []
            },
            "id": 3,
            "malicious": "yes",
            "name": "MALWARE_OBJECT",
            "occurred": "2021-02-14 09:45:58 +0000",
            "product": "EMAIL_MPS",
            "scVersion": "1115.212",
            "severity": "MAJR",
            "smtpMessage": {
                "subject": "test"
            },
            "src": {
                "smtpMailFrom": "test@malicious.net"
            },
            "uuid": "da0a1ee3-da28-46fa-9e5d-6663a76babba",
            "vlan": 0
        }
    }
}
```

#### Human Readable Output

>### FireEye Email Security Alerts:
>|id|occurred|product|name|malicious|action|src|dst|severity|alertUrl|
>|---|---|---|---|---|---|---|---|---|---|
>| 3 | 2021-02-14 09:45:58 +0000 | EMAIL_MPS | MALWARE_OBJECT | yes | notified | smtpMailFrom: test@malicious.net | smtpTo: test@actualdomain.org | MAJR | https://FireEyeEX/emps/eanalysis?e_id=12&type=url |


### fireeye-ex-get-artifacts-by-uuid
***
Downloads malware artifacts data for the specified UUID as a zip file.


#### Base Command

`fireeye-ex-get-artifacts-by-uuid`
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
```!fireeye-ex-get-artifacts-by-uuid uuid=44f2a6f0-aa3f-451d-956f-25565671c4d3```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "452@2c246757-e02c-458a-8620-dbc236283fb8",
        "Extension": "zip",
        "Info": "application/zip",
        "Name": "artifacts_44f2a6f0-aa3f-451d-956f-25565671c4d3.zip",
        "Size": 401,
        "Type": "Zip archive data, at least v2.0 to extract"
    }
}
```

#### Human Readable Output



### fireeye-ex-get-artifacts-metadata-by-uuid
***
Gets artifacts metadata for the specified UUID.


#### Base Command

`fireeye-ex-get-artifacts-metadata-by-uuid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | The universally unique identifier (UUID) for the alert. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.Alerts.uuid | string | Universally unique ID \(UUID\) of the alert. | 
| FireEyeEX.Alerts.artifactsInfoList.artifactType | string | The artifact type. | 
| FireEyeEX.Alerts.artifactsInfoList.artifactName | string | The artifact name. | 
| FireEyeEX.Alerts.artifactsInfoList.artifactSize | string | The zipped artifact size in bytes. | 


#### Command Example
```!fireeye-ex-get-artifacts-metadata-by-uuid uuid=44f2a6f0-aa3f-451d-956f-25565671c4d3```

#### Context Example
```json
{
    "FireEyeEX": {
        "Alerts": {
            "artifactsInfoList": [
                {
                    "artifactName": "name",
                    "artifactSize": "269",
                    "artifactType": "original_email"
                }
            ],
            "uuid": "uuid"
        }
    }
}
```

#### Human Readable Output

>### FireEye Email Security 44f2a6f0-aa3f-451d-956f-25565671c4d3 Artifact metadata:
>|artifactName|artifactSize|artifactType|
>|---|---|---|
>| name | 269 | original_email |


### fireeye-ex-get-quarantined-emails
***
Searches and retrieves quarantined emails.


#### Base Command

`fireeye-ex-get-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Specifies the start time of the search. This filter is optional. Default is last day. Syntax: start_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. Default is 1 day. | Optional | 
| end_time | Specifies the end time of the search. Default is now. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. | Optional | 
| from | The sender email. | Optional | 
| subject | The email subject. Must be URL encoded. | Optional | 
| appliance_id | The appliance ID. | Optional | 
| limit | The number of emails to return. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.QuarantinedEmail.appliance_id | string | The appliance ID associated with the quarantined email. | 
| FireEyeEX.QuarantinedEmail.completed_at | string | The time the email was quarantined. | 
| FireEyeEX.QuarantinedEmail.email_uuid | string | The quarantined email UUID. | 
| FireEyeEX.QuarantinedEmail.from | string | The quarantined email sender. | 
| FireEyeEX.QuarantinedEmail.message_id | string | The quarantined email message ID. | 
| FireEyeEX.QuarantinedEmail.quarantine_path | string | The quarantined email path. | 
| FireEyeEX.QuarantinedEmail.The quarantined email queue id. | string | The quarantined email queue ID. | 
| FireEyeEX.QuarantinedEmail.subject | string | The quarantined email subject. | 


#### Command Example
```!fireeye-ex-get-quarantined-emails limit=2```

#### Context Example
```json
{
    "FireEyeEX": {
        "QuarantinedEmail": [
            {
                "completed_at": "2021-06-14T16:01:15",
                "email_uuid": "uuid",
                "from": "undisclosed_sender",
                "message_id": "queue-id-queue@no-message-id",
                "quarantine_path": "/data/email-analysis/quarantine2/2021-06-14/16/queue",
                "queue_id": "queue",
                "subject": "test"
            },
            {
                "completed_at": "2021-06-14T16:01:15",
                "email_uuid": "uuid",
                "from": "undisclosed_sender",
                "message_id": "queue-id-queue@no-message-id",
                "quarantine_path": "/data/email-analysis/quarantine2/2021-06-14/16/queue",
                "queue_id": "queue",
                "subject": "test"
            }
        ]
    }
}
```

#### Human Readable Output

>### FireEye Email Security Quarantined emails:
>|email_uuid|from|subject|message_id|completed_at|
>|---|---|---|---|---|
>| uuid | undisclosed_sender | test | queue-id-queue@no-message-id | 2021-06-14T16:01:15 |
>| uuid | undisclosed_sender | test | queue-id-queue@no-message-id | 2021-06-14T16:01:15 |


### fireeye-ex-release-quarantined-emails
***
Releases and deletes quarantined emails. This is not available when Email Security is in Drop mode.


#### Base Command

`fireeye-ex-release-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_ids | The quarantined emails queue IDs. Supports up to 100 IDs. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fireeye-ex-delete-quarantined-emails
***
Deletes quarantined emails. This is not available when Email Security is in Drop mode.


#### Base Command

`fireeye-ex-delete-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_ids | The quarantined emails queue IDs. Supports up to 100 IDs. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fireeye-ex-download-quarantined-emails
***
Download quarantined emails.


#### Base Command

`fireeye-ex-download-quarantined-emails`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| queue_id | The quarantined emails queue ID. | Required | 


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
```!fireeye-ex-download-quarantined-emails queue_id=queue```

#### Context Example
```json
{
    "File": {
        "EntryID": "479@2c246757-e02c-458a-8620-dbc236283fb8",
        "Extension": "eml",
        "Info": "message/rfc822",
        "MD5": "b0320e23db6da746c694b79a60dac111",
        "Name": "queue.eml",
        "SHA1": "af85d7ebeeb359d94ea9a4d363acc429845042cf",
        "SHA256": "e543f92e16f3eab595c9167e8739afd38156065e1c7c41a27ed399e14cd4cf2e",
        "SHA512": "28a34e0042efa0a7b7dc865c9ce8f178228ccdb9f6d7fde11addef0bdbed95837bd3de4cbda79575be1ce67740d5e23634a63667de5f2c5a4f3b1209f6fd0f1e",
        "SSDeep": "6:tnWrw+bcnWd4jXQ93f9FfZPl1WbZiAi1rzfSY4SXfT8oERf:tnWrwWcnWd4M9fZfWbG4MfPE5",
        "Size": 269,
        "Type": "RFC 822 mail text, ASCII text"
    }
}
```

#### Human Readable Output



### fireeye-ex-get-reports
***
Returns reports on selected alerts.


#### Base Command

`fireeye-ex-get-reports`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_type | The report type. Possible values are: empsEmailAVReport, empsEmailActivity, empsEmailExecutiveSummary, empsEmailHourlyStat, mpsCallBackServer, mpsExecutiveSummary, mpsInfectedHostsTrend, mpsMalwareActivity, mpsWebAVReport, alertDetailsReport. | Required | 
| start_time | Specifies the start time of the search. This filter is optional. Syntax: start_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. Default is 1 week. | Optional | 
| end_time | Specifies the end time of the search. Default is now. Syntax: end_time=YYYY-MM-DDTHH:mm:ss.sss-OH:om or '1 day/month/year'. | Optional | 
| limit | Sets the maximum number (N) of items covered by each report. This option is required only for IPS TopN reports. Default is 100. | Optional | 
| interface | Sets ihe internet interface. Possible values are: A, B, AB. This option is required only for IPS reports. | Optional | 
| alert_id | Alert ID. This argument is only relevant when retrieving a report of type alertDetailsReport. | Optional | 
| infection_id | Infection ID. This argument is only relevant when retrieving a report of type alertDetailsReport in conjunction with the infection_type argument. | Optional | 
| infection_type | Infection Type. This argument is only relevant when retrieving a report of type alertDetailsReport in conjunction with the infection_id argument. Possible values are: malware-object, malware-callback, infection-match, domain-match, web-infection. | Optional | 
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
```!fireeye-ex-get-reports report_type=alertDetailsReport alert_id=3```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "475@2c246757-e02c-458a-8620-dbc236283fb8",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "report_alertDetailsReport_1623743836.790785.pdf",
        "Size": 0,
        "Type": "empty"
    }
}
```

#### Human Readable Output



### fireeye-ex-list-allowedlist
***
Lists the allowed sender domain by type.


#### Base Command

`fireeye-ex-list-allowedlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of objects to retrieve. Possible values are: sender_email_address, sender_domain, sender_ip_address, recipient_email_address, url, md5sum. | Required | 
| limit | The number of entries to return. Default is 20. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.name | string | The allowed domain name. | 
| FireEyeEX.created-at | string | The time the domain name was added to the list. | 
| FireEyeEX.matches | string | The number of matches for the domain name when compared against the incoming emails. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-ex-create-allowedlist
***
Creates allowed sender domain.


#### Base Command

`fireeye-ex-create-allowedlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of objects to retrieve. Possible values are: sender_email_address, sender_domain, sender_ip_address, recipient_email_address, url, md5sum. | Required | 
| entry_value | The entry value we want to create. | Required | 
| matches | The number of matches for the domain name when compared against the incoming emails. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.name | string | The allowed domain name. | 
| FireEyeEX.created-at | string | The time the domain name was added to the list. | 
| FireEyeEX.matches | string | The number of matches for the domain name against the incoming emails. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-ex-update-allowedlist
***
Updates allowed sender domain.


#### Base Command

`fireeye-ex-update-allowedlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of objects to retrieve. Possible values are: sender_email_address, sender_domain, sender_ip_address, recipient_email_address, url, md5sum. | Required | 
| entry_value | The entry value we want to update. | Required | 
| matches | The number of matches for the domain name when compared against the incoming emails. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.name | string | The allowed domain name. | 
| FireEyeEX.created-at | string | The time the domain name was added to the list. | 
| FireEyeEX.matches | string | The number of matches for the domain name when compared against the incoming emails. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-ex-delete-allowedlist
***
Deletes allowed sender domain.


#### Base Command

`fireeye-ex-delete-allowedlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of objects to retrieve. Possible values are: sender_email_address, sender_domain, sender_ip_address, recipient_email_address, url, md5sum. | Required | 
| entry_value | The entry value we want to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.name | string | The allowed domain name. | 
| FireEyeEX.created-at | string | The time the domain name was added to the list. | 
| FireEyeEX.matches | string | The number of matches for the domain name when compared against the incoming emails. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-ex-list-blockedlist
***
Lists the blocked sender domain by type.


#### Base Command

`fireeye-ex-list-blockedlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of objects to retrieve. Possible values are: sender_email_address, sender_domain, sender_ip_address, recipient_email_address, url, md5sum. | Required | 
| limit | The number of entries to return. Default is 20. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.name | string | The allowed domain name. | 
| FireEyeEX.created-at | string | The time the domain name was added to the list. | 
| FireEyeEX.matches | string | The number of matches for the domain name when compared against the incoming emails. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-ex-create-blockedlist
***
Creates blocked sender domain.


#### Base Command

`fireeye-ex-create-blockedlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of objects to retrieve. Possible values are: sender_email_address, sender_domain, sender_ip_address, recipient_email_address, url, md5sum. | Required | 
| entry_value | The entry value we want to create. | Required | 
| matches | The number of matches for the domain name when compared against the incoming emails. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.name | string | The allowed domain name. | 
| FireEyeEX.created-at | string | The time the domain name was added to the list. | 
| FireEyeEX.matches | string | The number of matches for the domain name when compared against the incoming emails. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-ex-update-blockedlist
***
Updates blocked sender domain.


#### Base Command

`fireeye-ex-update-blockedlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of objects to retrieve. Possible values are: sender_email_address, sender_domain, sender_ip_address, recipient_email_address, url, md5sum. | Required | 
| entry_value | The entry value we want to update. | Required | 
| matches | The number of matches for the domain name when compared against the incoming emails. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.name | string | The allowed domain name. | 
| FireEyeEX.created-at | string | The time the domain name was added to the list. | 
| FireEyeEX.matches | string | The number of matches for the domain name when compared against the incoming emails. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-ex-delete-blockedlist
***
Deletes blocked sender domain.


#### Base Command

`fireeye-ex-delete-blockedlist`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The type of objects to retrieve. Possible values are: sender_email_address, sender_domain, sender_ip_address, recipient_email_address, url, md5sum. | Required | 
| entry_value | The entry value we want to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeEX.name | string | The allowed domain name. | 
| FireEyeEX.created-at | string | The time the domain name was added to the list. | 
| FireEyeEX.matches | string | The number of matches for the domain name when compared against the incoming emails. | 


#### Command Example
``` ```

#### Human Readable Output


## Known Limitations
Clicking the **Test** button of the **Integration instance settings** window verifies that the instance configuration is correct.
Due to a known limitation, clicking the **Test** button several times in quick succession may result in an "Unauthorized" error, even after a successful result was initially returned. It is enough to receive one success message to verify that the configuration is correct. "Unauthorized" error messages received from repeated clicking of the instance configuration **Test** button do not affect the validity of the instance if the initial response was successful.