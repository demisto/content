Exabeam Data Lake provides a searchable log management system. 
Data Lake is used for log collection, storage, processing, and presentation.
This integration was integrated and tested with version LMS-i40.3 of Exabeam Data Lake.

## Configure Exabeam Data Lake in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| User Name |  | True |
| Password |  | True |
| Cluster Name | The default value is usually 'local', suitable for standard setups. For custom cluster deployments, consult Exabeam Support Team. | True |
| Trust any certificate (not secure) |  |  |
| Use system proxy settings |  |  |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### exabeam-data-lake-search

***
Get events from Exabeam Data Lake.

#### Base Command

`exabeam-data-lake-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The search query string to filter the events by. Examples can be found in the syntax documentation section of the integration description. | Required | 
| start_time | The starting date for the search range. The search range should be at least one day long and can extend up to a maximum of 10 days. | Required | 
| end_time | The ending date for the search range. This defines the end of the search range, which should be within one to ten days after the start_time. | Required | 
| limit | The maximal number of results to return. Maximum value is 3000. | Optional | 
| page | The page number for pagination. | Optional | 
| page_size | The maximal number of results to return per page. Maximum value is 3000. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExabeamDataLake.Event._id | str | The event ID. | 
| ExabeamDataLake.Event._source.Vendor | str | Vendor of the event. | 
| ExabeamDataLake.Event._source.Product | str | Product of the event. | 
| ExabeamDataLake.Event._source.@timestamp | str | The time of the event. | 
| ExabeamDataLake.Event._source.message | str | The message of the event. | 

#### Command example
```!exabeam-data-lake-search query="risk_score:3" start_time="2024.02.27" end_time="2024.02.28" limit=2```
#### Context Example
```json
{
    "ExabeamDataLake": {
        "Event": [
            {
                "_id": "some_id",
                "_index": "exabeam-2024.02.28",
                "_routing": "SfA86vqw",
                "_score": null,
                "_source": {
                    "@timestamp": "2024-02-28T16:15:50.614Z",
                    "@version": "1",
                    "Product": "Exabeam AA",
                    "Vendor": "Exabeam",
                    "data_type": "exabeam-security-alert",
                    "exa_activity_type": [
                        "alert/security",
                        "alert"
                    ],
                    "exa_adjustedEventTime": "2024-02-28T16:15:29.000Z",
                    "exa_category": "Exabeam Alerts",
                    "exa_device_type": [
                        "security"
                    ],
                    "exa_rawEventTime": "2024-02-28T16:15:29.000Z",
                    "indexTime": "2024-02-28T16:15:51.626Z",
                    "is_ransomware_src_ip": false,
                    "is_threat_src_ip": false,
                    "is_tor_src_ip": false,
                    "log_type": "dlp-alert",
                    "message": "<86>1 2024-02-28T16:15:50.609Z exabeam-analytics-master Exabeam - - - timestamp=\"2024-02-28T16:15:29.192Z\" score=\"3\" user=\"ghardin\" event_time=\"2024-02-28 14:35:35\" event_type=\"dlp-alert\" domain=\"kenergy\" time=\"1709130935833\" source=\"ObserveIT\" vendor=\"ObserveIT\" lockout_id=\"NA\" session_id=\"ghardin-20240228143533\" session_order=\"2\" account=\"ghardin\" getvalue('zone_info', src)=\"new york office\" alert_name=\" rule violation\" local_asset=\"lt-ghardin-888\" alert_type=\"DATA EXFILTRATION\" os=\"Win\" rule_name=\"Abnormal DLP alert name for user\" rule_description=\"Exabeam noted that this alert name has been triggered for this user in the past yet it is still considered abnormal activity. This activity may be an early indication of compromise of a user by malware or other malicious actors.\" rule_reason=\"Abnormal DLP alert with name  rule violation for user\" ",
                    "port": 41590,
                    "risk_score": "3",
                    "rule_description": "Exabeam noted that this alert name has been triggered for this user in the past yet it is still considered abnormal activity. This activity may be an early indication of compromise of a user by malware or other malicious actors.",
                    "rule_name": "Abnormal DLP alert name for user",
                    "score": "3",
                    "session_id": "ghardin-20240228143533",
                    "time": "2024-02-28T16:15:29.000Z",
                    "user": "ghardin"
                },
                "_type": "logs",
                "sort": [
                    1709136950614
                ]
            },
            {
                "_id": "another_id",
                "_index": "exabeam-2024.02.27",
                "_routing": "XUXxevyv",
                "_score": null,
                "_source": {
                    "@timestamp": "2024-02-27T16:21:45.721Z",
                    "@version": "1",
                    "Product": "Exabeam AA",
                    "Vendor": "Exabeam",
                    "data_type": "exabeam-security-alert",
                    "event_code": "4768",
                    "exa_activity_type": [
                        "alert/security",
                        "alert"
                    ],
                    "exa_adjustedEventTime": "2024-02-24T16:16:29.000Z",
                    "exa_category": "Exabeam Alerts",
                    "exa_device_type": [
                        "security"
                    ],
                    "exa_rawEventTime": "2024-02-24T16:16:29.000Z",
                    "host": "exabeamdemodc1",
                    "indexTime": "2024-02-27T16:23:56.271Z",
                    "is_ransomware_dest_ip": false,
                    "is_threat_dest_ip": false,
                    "is_tor_dest_ip": false,
                    "log_type": "kerberos-logon",
                    "message": "<86>1 2024-02-27T16:21:45.539Z exabeam-analytics-master Exabeam - - - timestamp=\"2024-02-24T16:16:29.975Z\" id=\"ghardin-20240224140716\" score=\"3\" user=\"ghardin\" event_time=\"2024-02-24 14:34:42\" event_type=\"kerberos-logon\" host=\"exabeamdemodc1\" domain=\"ktenergy\" time=\"1708785282052\" source=\"DC\" lockout_id=\"NA\" session_id=\"ghardin-20240224140716\" session_order=\"4\" account=\"ghardin\" ticket_options_encryption=\"0x40810010:0x12\" nonmachine_user=\"ghardin\" event_code=\"4768\" ticket_encryption_type=\"0x12\" ticket_options=\"0x40810010\" rule_name=\"IT presence without badge access\" rule_description=\"This user is logged on to the company network but did not use their badge to access a physical location. It is unusual to have IT access without badge access.\" rule_reason=\"IT presence without badge access\" ",
                    "port": 56920,
                    "risk_score": "3",
                    "rule_description": "This user is logged on to the company network but did not use their badge to access a physical location. It is unusual to have IT access without badge access.",
                    "rule_name": "IT presence without badge access",
                    "score": "3",
                    "session_id": "ghardin-20240224140716",
                    "time": "2024-02-24T16:16:29.000Z",
                    "user": "ghardin"
                },
                "_type": "logs",
                "sort": [
                    1709050905721
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Logs
>|Created_at|Id|Message|Product|Vendor|
>|---|---|---|---|---|
>| 2024-02-28T16:15:50.614Z | some_id | <86>1 2024-02-28T16:15:50.609Z exabeam-analytics-master Exabeam - - - timestamp="2024-02-28T16:15:29.192Z" id="ghardin-20240228143533" score="3" user="ghardin" event_time="2024-02-28 14:35:35" event_type="dlp-alert" domain="kenergy" time="1709130935833" source="ObserveIT" vendor="ObserveIT" lockout_id="NA" session_id="ghardin-20240228143533" session_order="2" account="ghardin" getvalue('zone_info', src)="new york office" alert_name=" rule violation" local_asset="lt-ghardin-888" alert_type="DATA EXFILTRATION" os="Win" rule_name="Abnormal DLP alert name for user" rule_description="Exabeam noted that this alert name has been triggered for this user in the past yet it is still considered abnormal activity. This activity may be an early indication of compromise of a user by malware or other malicious actors." rule_reason="Abnormal DLP alert with name  rule violation for user"  | Exabeam AA | Exabeam |
>| 2024-02-27T16:21:45.721Z | another_id | <86>1 2024-02-27T16:21:45.539Z exabeam-analytics-master Exabeam - - - timestamp="2024-02-24T16:16:29.975Z" id="ghardin-20240224140716" score="3" user="ghardin" event_time="2024-02-24 14:34:42" event_type="kerberos-logon" host="exabeamdemodc1" domain="ktenergy" time="1708785282052" source="DC" lockout_id="NA" session_id="ghardin-20240224140716" session_order="4" account="ghardin" ticket_options_encryption="0x40810010:0x12" nonmachine_user="ghardin" event_code="4768" ticket_encryption_type="0x12" ticket_options="0x40810010" rule_name="IT presence without badge access" rule_description="This user is logged on to the company network but did not use their badge to access a physical location. It is unusual to have IT access without badge access." rule_reason="IT presence without badge access"  | Exabeam AA | Exabeam |
