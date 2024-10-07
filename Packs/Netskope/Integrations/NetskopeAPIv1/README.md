## Netskope (API v1)

Get alerts and events, manage quarantine files as well as URL and hash lists using Netskope API v1.
This integration was integrated and tested with version 93.0.7.625 of Netskope.

## Configure Netskope in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API token |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Maximum incidents per fetch |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, like 12 hours, 7 days) |  | False |
| Fetch Events | Fetch events as incidents, in addition to the alerts. | False |
| Event types to fetch |  | False |
| Maximum events as incidents per fetch |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### netskope-event-list
***
Get events extracted from SaaS traffic and or logs.


#### Base Command

`netskope-event-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Free query to filter the events. For example, "app eq Dropbox". For more information, please visit Netskope documentation: https://docs.netskope.com/en/get-events-data.html' | Optional |
| event_type | Select events by their type. Possible values are: page, application, audit, infrastructure, network. | Required |
| timeperiod | Get all events from a certain time period. Possible values are: Last 60 mins, Last 24 Hrs, Last 7 Days, Last 30 Days. | Optional |
| start_time | Restrict events to those that have timestamps greater than the provided timestamp. | Optional |
| end_time | Restrict events to those that have timestamps less than or equal to the provided timestamp. | Optional |
| insertion_start_time | Restrict events to those that were inserted to the system after the provided timestamp. | Optional |
| insertion_end_time | Restrict events to those that were inserted to the system before the provided timestamp. | Optional |
| limit | The maximum amount of events to retrieve. Default is 50. | Optional |
| page | The page number of the events to retrieve (minimum is 1). Default is 1. | Optional |
| unsorted | If true, the returned data will not be sorted (useful for improved performance). Possible values are: true, false. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.Event.event_id | String | The unique identifier of the event. |
| Netskope.Event.timestamp | Number | Unix epoch timestamp when the event happened in. |
| Netskope.Event.type | String | Shows if it is an application event or a connection event. |
| Netskope.Event.access_method | String | Cloud app traffic can be steered to the Netskope cloud using different deployment methods such as Client \(Netskope Client\), Secure Forwarder etc. |
| Netskope.Event.traffic_type | String | Type of the traffic: CloudApp or Web. |
| Netskope.Event.count | Number | Number of raw log lines/events sessionized or suppressed during the suppressed interval. |
| Netskope.Event.app | String | Specific cloud application used by the user \(e.g. app = Dropbox\). |
| Netskope.Event.appcategory | String | Application Category as designated by Netskope. |
| Netskope.Event.url | String | URL of the application that the user visited as provided by the log or data plane traffic. |
| Netskope.Event.page | String | The URL of the originating page. |
| Netskope.Event.domain | String | Domain value. |
| Netskope.Event.object | String | Name of the object which is being acted on. |
| Netskope.Event.object_id | String | Unique ID associated with an object. |
| Netskope.Event.activity | String | Description of the user performed activity. |
| Netskope.Event.device | String | Device type from where the user accessed the cloud app. |
| Netskope.Event.category | String | The event category. |

#### Command example
```!netskope-event-list event_type=application limit=1 start_time=2021-03-21T18:48:02.358736 end_time=2022-03-21T18:48:02.358736```
#### Context Example
```json
{
    "Netskope": {
        "Event": {
            "_insertion_epoch_timestamp": 1647890592,
            "access_method": "API Connector",
            "activity": "Create",
            "alert": "no",
            "app": "Google Workspace",
            "appcategory": "Application Suite",
            "audit_category": null,
            "audit_type": "authorize",
            "browser": "unknown",
            "category": "Application Suite",
            "cci": 91,
            "ccl": "excellent",
            "count": 1,
            "device": "Other",
            "event_id": "a3f6cb3f22c4431defbf371b",
            "from_user": "test@goxsoar.com",
            "from_user_category": "Internal",
            "instance_id": "goxsoar.com",
            "netskope_activity": "False",
            "object": "BetterCloud",
            "object_id": "800521135851.apps.googleusercontent.com",
            "object_type": "Token",
            "organization_unit": "",
            "os": "unknown",
            "other_categories": [],
            "scopes": [
                "https://apps-apis.google.com/a/feeds/calendar/resource/",
                "https://apps-apis.google.com/a/feeds/compliance/audit/",
                "https://apps-apis.google.com/a/feeds/domain/",
                "https://apps-apis.google.com/a/feeds/emailsettings/2.0/",
                "https://docs.google.com/feeds/",
                "https://sites.google.com/feeds/",
                "https://spreadsheets.google.com/feeds/",
                "https://www.google.com/m8/feeds/",
                "https://www.googleapis.com/auth/contacts",
                "https://www.googleapis.com/auth/activity",
                "https://www.googleapis.com/auth/admin.datatransfer",
                "https://www.googleapis.com/auth/admin.directory.group",
                "https://www.googleapis.com/auth/admin.directory.group.member",
                "https://www.googleapis.com/auth/admin.directory.orgunit",
                "https://www.googleapis.com/auth/admin.directory.user",
                "https://www.googleapis.com/auth/admin.directory.user.alias",
                "https://www.googleapis.com/auth/admin.directory.user.security",
                "https://www.googleapis.com/auth/admin.directory.userschema",
                "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                "https://www.googleapis.com/auth/admin.reports.usage.readonly",
                "https://www.googleapis.com/auth/apps.groups.settings",
                "https://www.googleapis.com/auth/apps.licensing",
                "https://www.googleapis.com/auth/calendar",
                "https://www.googleapis.com/auth/drive",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/gmail.settings.basic",
                "https://www.googleapis.com/auth/gmail.settings.sharing"
            ],
            "site": "Google App Suite",
            "srcip": "fda3:e722:ac3:10:15:8d06:a37:f8d0",
            "timestamp": 1647888482,
            "traffic_type": "CloudApp",
            "type": "nspolicy",
            "ur_normalized": "test@goxsoar.com",
            "user": "test@goxsoar.com",
            "user_category": "Internal",
            "userip": "fda3:e722:ac3:10:15:8d06:a37:f8d0",
            "userkey": "test@goxsoar.com"
        }
    }
}
```

#### Human Readable Output

>### Events List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|Event Id|Timestamp|Type|Access Method|App|Traffic Type|
>|---|---|---|---|---|---|
>| a3f6cb3f22c4431defbf371b | 1647888482 | nspolicy | API Connector | Google Workspace | CloudApp |


### netskope-alert-list
***
Get alerts generated by Netskope, including policy, DLP, and watch list alerts.


#### Base Command

`netskope-alert-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Free query to filter the alerts. For example, "alert_name like 'test'". For more information, please visit Netskope documentation: https://docs.netskope.com/en/get-alerts-data.html' | Optional |
| alert_type | Select alerts by their type. Possible values are: anomaly, Compromised Credential, policy, Legal Hold, malsite, Malware, DLP, Security Assessment, watchlist, quarantine, Remediation, uba. | Optional |
| acked | Whether to retrieve acknowledged alerts or not. Possible values are: true, false. | Optional |
| timeperiod | Get alerts from certain time period. Possible values are: Last 60 mins, Last 24 Hrs, Last 7 Days, Last 30 days, Last 60 days, Last 90 days. | Optional |
| start_time | Restrict alerts to those that have timestamps greater than the provided timestamp. | Optional |
| end_time | Restrict alerts to those that have timestamps less than or equal to the provided timestamp. | Optional |
| insertion_start_time | Restrict alerts which have been inserted into the system after the provided timestamp. | Optional |
| insertion_end_time | Restrict alerts which have been inserted into the system before the provided timestamp. | Optional |
| limit | The maximum number of alerts to return. Default is 50. | Optional |
| page | The page number of the alerts to retrieve (minimum is 1). Default is 1. | Optional |
| unsorted | If true, the returned data will not be sorted (useful for improved performance). Possible values are: true, false. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.Alert.alert_id | String | The unique identifier of the alert. |
| Netskope.Alert.timestamp | Number | Timestamp when the event/alert happened. |
| Netskope.Alert.type | String | Shows if it is an application event or a connection event. |
| Netskope.Alert.access_method | String | Cloud app traffic can be steered to the Netskope cloud using different deployment methods such as Client \(Netskope Client\), Secure Forwarder etc. |
| Netskope.Alert.traffic_type | String | Type of the traffic: CloudApp or Web. |
| Netskope.Alert.action | String | Action taken on the event for the policy. |
| Netskope.Alert.count | Number | Number of raw log lines/events sessionized or suppressed during the suppressed interval. |
| Netskope.Alert.alert_name | String | Name of the alert. |
| Netskope.Alert.alert_type | String | Type of the alert. |
| Netskope.Alert.acked | Boolean | Whether user acknowledged the alert or not. |
| Netskope.Alert.policy | String | Name of the policy configured by an admin. |
| Netskope.Alert.app | String | Specific cloud application used by the user \(e. |
| Netskope.Alert.appcategory | String | Application Category as designated by Netskope. |
| Netskope.Alert.dlp_file | String | File/Object name extracted from the file/object. |
| Netskope.Alert.dlp_profile | String | DLP profile name. |
| Netskope.Alert.dlp_rule | String | DLP rule that triggered. |
| Netskope.Alert.category | String | The alert category. |
| Netskope.Alert.cci | Number | The cloud confidence index. |

#### Command example
```!netskope-alert-list limit=1 start_time=2021-03-21T18:48:02.358736 end_time=2022-03-21T18:48:02.358736```
#### Context Example
```json
{
    "Netskope": {
        "Alert": {
            "_insertion_epoch_timestamp": 1647888457,
            "access_method": "API Connector",
            "acked": "false",
            "action": "alert",
            "activity": "Introspection Scan",
            "alert": "yes",
            "alert_id": "0d7fa7e3cb3034bcc0ff94a5",
            "alert_name": "Gdrive - Alert on PII",
            "alert_type": "DLP",
            "app": "Google Drive",
            "appcategory": "Cloud Storage",
            "browser": "unknown",
            "category": "Cloud Storage",
            "cci": 91,
            "ccl": "excellent",
            "count": 1,
            "device": "Other",
            "dlp_file": "CS Owned PC Data",
            "dlp_incident_id": 1407319677213026800,
            "dlp_is_unique_count": "true",
            "dlp_parent_id": 1407319677213026800,
            "dlp_profile": "Best Practice PII DLP Profile",
            "dlp_rule": "FullName-Near-SSN-Unique",
            "dlp_rule_count": 64,
            "dlp_rule_severity": "High",
            "dlp_unique_count": 63,
            "dst_country": "US",
            "dst_latitude": 37.4059906006,
            "dst_location": "Mountain View",
            "dst_longitude": -122.0785140991,
            "dst_region": "California",
            "dst_timezone": "America/Los_Angeles",
            "dst_zipcode": "N/A",
            "dstip": "142.250.191.78",
            "exposure": "internal",
            "file_lang": "ENGLISH",
            "file_path": "/My Drive/CS Owned PC Data",
            "file_size": 805733,
            "file_type": "application/vnd.google-apps.spreadsheet",
            "from_user": "test@goxsoar.com",
            "instance": "goxsoar.com",
            "instance_id": "goxsoar.com",
            "internal_collaborator_count": 20,
            "md5": "81e5926346f19f158688ccf40d88436e",
            "mime_type": "application/vnd.google-apps.spreadsheet",
            "modified": 1647888385,
            "netskope_pop": "US-SJC1",
            "object": "CS Owned PC Data",
            "object_id": "1wxnfr3SWylRdPx8R3WHo2ywml7LsYPSt_6wqUX2KuDU",
            "object_type": "File",
            "organization_unit": "",
            "os": "unknown",
            "other_categories": [],
            "outer_doc_type": 361,
            "owner": "test@goxsoar.com",
            "policy": "Gdrive - Alert on PII",
            "request_id": 6525954495577788000,
            "scan_type": "Ongoing",
            "sha256": "3f53dac4dbce5fbc982ba3180b1b5d5fbed2a9c1cacf906471ce6a9aeef08a05",
            "shared_with": "support@goxsoar.com",
            "site": "Google Drive",
            "suppression_key": "CS Owned PC Data",
            "timestamp": 1647888450,
            "title": "CS Owned PC Data",
            "total_collaborator_count": 20,
            "traffic_type": "CloudApp",
            "true_obj_category": "Spreadsheet",
            "true_obj_type": "Microsoft Excel 2007 XML",
            "type": "nspolicy",
            "ur_normalized": "test@goxsoar.com",
            "url": "https://drive.google.com/open?id=4wxnfr3SWylRdPx8R3WHo2ywml7LsYPSt_6wqUX2KuDU",
            "user": "test@goxsoar.com",
            "user_id": "test@goxsoar.com",
            "userkey": "test@goxsoar.com"
        }
    }
}
```

#### Human Readable Output

>### Alerts List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|Alert Id|Alert Name|Alert Type|Timestamp|Action|
>|---|---|---|---|---|
>| 0d7fa7e3cb3034bcc0ff94a5 | Gdrive - Alert on PII | DLP | 1647888450 | alert |


### netskope-quarantined-file-list
***
List all quarantined files.


#### Base Command

`netskope-quarantined-file-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | Get files last modified after the provided date string. | Optional |
| end_time | Get files last modified before the provided date string. | Optional |
| limit | The maximum amount of clients to retrieve. Default is 50. | Optional |
| page | The page number of the clients to retrieve (minimum is 1). Default is 1. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.Quarantine.quarantine_profile_id | String | The ID of quarantine profile. |
| Netskope.Quarantine.quarantine_profile_name | String | The name of quarantine profile. |
| Netskope.Quarantine.file_id | String | The ID of the quarantined file. |
| Netskope.Quarantine.original_file_name | String | The original filename before quarantining. |
| Netskope.Quarantine.policy | String | The policy name caused quarantine the file. |
| Netskope.Quarantine.quarantined_file_name | String | The filename after quarantining. |
| Netskope.Quarantine.user_id | String | The ID of the user related to the quarantined file. |

#### Command example
```!netskope-quarantined-file-list limit=1```
#### Context Example
```json
{
    "Netskope": {
        "Quarantine": {
            "file_id": "1M_RU4jLPUwclKOhqZ7sPSqkMNS-S6Vyr",
            "original_file_name": "PII SSN Large v2.xlsx",
            "policy": "[Data Protection] - Quarantine PII Uploads to Box",
            "quarantine_profile_id": "1",
            "quarantine_profile_name": "Qmasters Testing Google Drive",
            "quarantined_file_name": "inline_884993759783_1_F2DD7F63_PII SSN Large v2.xlsx",
            "user_id": "test@goxsoar.com"
        }
    }
}
```

#### Human Readable Output

>### Quarantined Files List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|quarantine_profile_id|quarantine_profile_name|file_id|original_file_name|policy|
>|---|---|---|---|---|
>| 1 | Qmasters Testing Google Drive | 1M_RU4jLPUwclKOhqZ7sPSqkMNS-S6Vyr | PII SSN Large v2.xlsx | [Data Protection] - Quarantine PII Uploads to Box |


### netskope-quarantined-file-get
***
Download a quarantined file.


#### Base Command

`netskope-quarantined-file-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| quarantine_profile_id | The ID of quarantine profile. | Required |
| file_id | The ID of the quarantined file. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | Number | The size of the file. |
| File.Name | String | The name of the file. |
| File.EntryID | String | The entry ID of the file. |
| File.Info | String | File information. |
| File.Type | String | The file type. |
| File.Extension | String | The file extension. |

#### Command example
```!netskope-quarantined-file-get file_id=1M_RU4jLPUwclKOhqZ7sPSqkMNS-S6Vyr quarantine_profile_id=1```
#### Context Example
```json
{
    "File": {
        "EntryID": "4447@8479e914-8493-4968-8f32-78852375d17b",
        "Extension": "zip",
        "Info": "application/zip",
        "MD5": "8ac692ef2cc78adfc523188e54d52933",
        "Name": "1M_RU4jLPUwclKOhqZ7sPSqkMNS-S6Vyr.zip",
        "SHA1": "19cf128ad8fd41108d0a601e8e9c8cf123c11c5a",
        "SHA256": "9ea98de9c4f852665f678338767280f64b20ed11943c49709440643ed04df122",
        "SHA512": "5a6bce0fd15e4184d29ee8d38627ec47150665a6ccb67d39b02a8898ff0c987c4e7be580c9243cc3d4a7f3f2b637f226216434bf01bc2babfe35a4b7ff8cc2cc",
        "SSDeep": "384:wc313ff+IizBt/oPervm6X61XWRcjDQJB9k3Wl:wMGIct/PjtX61EVB9mWl",
        "Size": 15774,
        "Type": "Microsoft Excel 2007+"
    }
}
```

#### Human Readable Output



### netskope-quarantined-file-update
***
Take an action on a quarantined file.


#### Base Command

`netskope-quarantined-file-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| quarantine_profile_id | The profile ID of the quarantined file. | Required |
| file_id | The ID of the quarantined file. | Required |
| action | Action to be performed on a quarantined. Possible values are: block, allow. | Required |


#### Context Output

There is no context output for this command.

#### Command example
!netskope-quarantined-file-update file_id=1M_RR4jLPUwclKOhqZ7sPSqkMNS-S6Vyr quarantine_profile_id=1 action=block

#### Human Readable Output

>The file 1M_RR4jLPUwclKOhqZ7sPSqkMNS-S6Vyr was successfully blocked!


### netskope-url-list-update
***
Update the URL List with the values provided.
The command will override the whole list content, rather than appending the new values.

#### Base Command

`netskope-url-list-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of an existing URL List shown in the Netskope UI on the URL List page. | Required |
| urls | The content of the URL list. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.URLList.name | String | The name of the URL list. |
| Netskope.URLList.URL | String | The content the URL list. |

#### Command example
```!netskope-url-list-update name="Allowed URLs" urls="allow.me,allow2.me"```
#### Context Example
```json
{
    "Netskope": {
        "URLList": {
            "URL": [
                "allow.me",
                "allow2.me"
            ],
            "name": "Allowed URLs"
        }
    }
}
```

#### Human Readable Output

>URL List Allowed URLs:
>allow.me, allow2.me

### netskope-file-hash-list-update
***
Update file hash list with the values provided.
The command will override the whole list content, rather than appending the new values.

#### Base Command

`netskope-file-hash-list-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of an existing file hash list shown in the Netskope UI on the file hash list page. | Required |
| hash | List of file hashes (md5 or sha256). | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FileHashList.name | String | The name of the hash list. |
| FileHashList.hash | String | The content of the hash list. |

#### Command example
```!netskope-file-hash-list-update name="Test SHA256" hash="00db7cf5cc13df9ae88615af999582608361c14fc915d1dd76fa619d1c341597"```
#### Context Example
```json
{
    "Netskope": {
        "FileHashList": {
            "hash": [
                "00db7cf5cc13df9ae88615af999582608361c14fc915d1dd76fa619d1c341597"
            ],
            "name": "Test SHA256"
        }
    }
}
```

#### Human Readable Output

>Hash List Test SHA256:
>00db7cf5cc13df9ae88615af999582608361c14fc915d1dd76fa619d1c341597

### netskope-client-list
***
Get information about the Netskope clients.


#### Base Command

`netskope-client-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Free query on the clients, based on the client fields. For example, "host_info.hostname eq xxx". For more information, please visit Netskope documentation: https://docs.netskope.com/en/get-client-data.html'. | Optional |
| limit | The maximum amount of clients to retrieve. Default is 50. | Optional |
| page | The page number of the clients to retrieve (minimum is 1). Default is 1. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.Client.client_id | String | The ID of the Netskope client. |
| Netskope.Client.client_version | String | The client version. |
| Netskope.Client.device_id | String | The ID of the client's device. |
| Netskope.Client.host_info | String | Information about the client's host. |
| Netskope.Client.last_event | String | Information about the last event related to the client. |
| Netskope.Client.user_added_time | String | The last time a client's user was added to Netskope. |
| Netskope.Client.users | String | List of all users of the provided client. |

#### Command example
```!netskope-client-list limit=1```
#### Context Example
```json
{
    "Netskope": {
        "Client": {
            "client_id": "TEST82A5",
            "client_version": "91.0.6.812",
            "device_id": "TEST82A5",
            "host_info": {
                "device_make": "Parallels Software International Inc.",
                "device_model": "Parallels Virtual Platform",
                "hostname": "TEST82A5",
                "managementID": "",
                "nsdeviceuid": "725DAC1A-6654-3F3A-971E-C984FBE9FE5E",
                "os": "Windows",
                "os_version": "10.0 (2009)"
            },
            "last_event": {
                "actor": "System",
                "event": "Tunnel Up",
                "npa_status": "Steering Disabled",
                "status": "Enabled",
                "timestamp": 1642475967
            },
            "user_added_time": 1638994653,
            "users": [
                {
                    "_id": "0c6f3f867882c2d243a83310",
                    "device_classification_status": "Not Configured",
                    "last_event": {
                        "actor": "System",
                        "event": "Tunnel Up",
                        "npa_status": "Steering Disabled",
                        "status": "Enabled",
                        "timestamp": 1642475967
                    },
                    "user_source": "Manual",
                    "user_state": 0,
                    "userkey": "W1Acv9LP05u2654lwRaD",
                    "username": "test@goxsoar.com"
                },
                {
                    "_id": "0c6f3f867882c2d243a83310",
                    "device_classification_status": "Unknown",
                    "last_event": {
                        "actor": "System",
                        "event": "Tunnel Down",
                        "npa_status": "Disabled",
                        "status": "Disabled",
                        "timestamp": 1638995110
                    },
                    "userkey": "W1Acv9LP05u2654lwRaD"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Clients List:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|Client Id|Client Version|Device Id|User Added Time|
>|---|---|---|---|
>| TEST82A5 | 91.0.6.812 | TEST82A5 | 1638994653 |


### netskope-host-associated-user-list
***
List all users of certain host by its hostname.


#### Base Command

`netskope-host-associated-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The hostname to view its users. | Required |
| limit | The maximum amount of users to retrieve. Default is 50. | Optional |
| page | The page number of the users to retrieve (minimum is 1). Default is 1. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.User.user_id | String | The ID of the Netskope user. |
| Netskope.User.device_classification_status | String | The device classification status. |
| Netskope.User.last_event | Unknown | Information about the last event related to the user. |
| Netskope.User.user_source | String | The source of the user. |
| Netskope.User.userkey | String | The user key. |
| Netskope.User.username | String | The name/email of the user. |

#### Command example
```!netskope-host-associated-user-list hostname=TEST82A5 limit=1```
#### Context Example
```json
{
    "Netskope": {
        "User": {
            "device_classification_status": "Unknown",
            "last_event": {
                "actor": "System",
                "event": "Tunnel Down",
                "npa_status": "Disabled",
                "status": "Disabled",
                "timestamp": 1638995110
            },
            "user_id": "0c6f3f867882c2d243a83310",
            "user_source": "Manual",
            "user_state": 0,
            "userkey": "W1Acv9LP05u2654lwRaD",
            "username": "test@goxsoar.com"
        }
    }
}
```

#### Human Readable Output

>### Users Associated With TEST82A5:
> Current page size: 1
> Showing page 1 out of others that may exist.
>|user_id|username|user_source|
>|---|---|---|
>| 0c6f3f867882c2d243a83310 | test@goxsoar.com | Manual |
>| 0c6f3f867882c2d243a83310 |  |  |


### netskope-user-associated-host-list
***
List all hosts related to a certain username.


#### Base Command

`netskope-user-associated-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username to view its hosts. | Required |
| limit | The maximum amount of hosts to retrieve. Default is 50. | Optional |
| page | The page number of the hosts to retrieve (minimum is 1). Default is 1. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Netskope.Host.nsdeviceuid | String | Netskope device UID. |
| Netskope.Host.os | String | The device operating system. |
| Netskope.Host.os_version | String | The device operating system version. |
| Netskope.Host.device_model | String | The device model. |
| Netskope.Host.hostname | String | The hostname of the device. |
| Netskope.Host.agent_status | String | The status of the agent on the device. |

#### Command example
```!netskope-user-associated-host-list username=test@goxsoar.com```
#### Context Example
```json
{
    "Netskope": {
        "Host": {
            "agent_status": "Enabled",
            "device_make": "Parallels Software International Inc.",
            "device_model": "Parallels Virtual Platform",
            "hostname": "TEST82A5",
            "managementID": "",
            "nsdeviceuid": "725DAC1A-6654-3F3A-971E-C984FBE9FE5E",
            "os": "Windows",
            "os_version": "10.0 (2009)"
        }
    }
}
```

#### Human Readable Output

>### Hosts Associated With test@goxsoar.com:
> Current page size: 50
> Showing page 1 out of others that may exist.
>|hostname|os_version|agent_status|
>|---|---|---|
>| TEST82A5 | 10.0 (2009) | Enabled |
