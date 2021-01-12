## Overview
---
Uptycs combines the open source universal agent, osquery, with a scalable security analytics platform for fleet visibility, intrusion detection, vulnerability monitoring and compliance.  Uptycs deploys osquery to your entire infrastructure, regardless of operating system mix or hosting environment, collects, and stores system state data.  Uptycs will stream that data over secure TLS protocol, storing it in your unique instance, and continuously monitoring for suspicious activity.  Integrated third party feeds of known malware, threats and over 170,000 indicators of compromise (IOCs) further enhance threat visibility.  Finally, take action with real-time alerts, dashboards and reports packaged for multiple security protocols.

The Demisto-Uptycs integration connects to the Uptycs backend via the Uptycs API.  The integration allows the use of Uptycs data in existing workflows.  Features include fetching and handling alerts, threat investigation, posting new threat sources, setting tags on assets, and the ability to run arbitrary SQL queries against your Uptycs database or in real-time against registered endpoints.

## Uptycs Playbook
---

1. Uptycs - Bad IP Incident and Uptycs - Outbound Connection to Threat IOC Incident
    Get details about connections which have been opened to known bad IP addresses, including process and parent process information, IP addresses, ports, sockets, and the source of the threat intelligence.

## Use Cases
---

*  Incident investigation
*  Fetch and handle alerts
*  Monitor asset activity
*  Audit and compliance
*  Vulnerability management
*  Mac EDR


## Configure Uptycs on Demisto
---

## How to get an API Key and API Secret
In order to create an instance of the integration, you need to download a user API key and secret from your Uptycs account.  

1. Go to your Uptycs environment.
2. Navigate to **Configuration > Users**.  
3. In the **User API key** section, click download.  
   The downloaded file will have all the information necessary to create the instance.

## Parameters
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for Uptycs.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __API key__
    * __API secret__
    * __API domain__: the domain found in your API key file as well as the Top Level Domain for your Uptycs stack (example: if your Uptycs' stack URL is "mystack.uptycs.io" then your API key file will say "mystack" in the domain field.  You would then put "mystack.uptycs.io" in the API domain field when configuring your integration instance).
    * __API customer_id__
    * __Fetch incidents__
    * __Incident type__
    * __Trust any certificate (unsecure)__
    * __Use system proxy__
    * __ First fetch since__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---
The Demisto-Uptycs integration creates incients from Uptycs alerts using the Uptycs API 


## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. uptycs-get-assets
2. uptycs-run-query
3. uptycs-get-alerts
4. uptycs-get-alert-rules
5. uptycs-get-event-rules
6. uptycs-get-events
7. uptycs-get-process-open-sockets
8. uptycs-get-process-information
9. uptycs-get-process-child-processes
10. uptycs-get-processes
11. uptycs-get-process-open-files
12. uptycs-set-alert-status
13. uptycs-set-asset-tag
14. uptycs-get-user-information
15. uptycs-get-threat-indicators
16. uptycs-get-threat-sources
17. uptycs-get-threat-vendors
18. uptycs-get-parent-information
19. uptycs-post-threat-source
20. uptycs-get-users
21. uptycs-get-asset-groups
22. uptycs-get-user-asset-groups
23. uptycs-get-threat-indicator
24. uptycs-get-threat-source
25. uptycs-get-process-events
26. uptycs-get-process-event-information
27. uptycs-get-socket-events
28. uptycs-get-parent-event-information
29. uptycs-get-socket-event-information
30. uptycs-get-asset-tags
31. uptycs-get-saved-queries
32. uptycs-run-saved-query
33. uptycs-post-saved-query
### 1. uptycs-get-assets
---
return assets enrolled with Uptycs
##### Base Command

`uptycs-get-assets`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_group_id | Only return assets which are a member of this asset group | Optional | 
| host_name_is | Only return assets with this hostname.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| host_name_like | Only return assets with this string in the hostname.  Use this to find a selection of assets with similar hostnames.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 
| os | Only return assets with this type of operating system. | Optional | 
| asset_id | Only return the asset with this unique asset id | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Assets.id | string | Uptycs asset id  | 
| Uptycs.Assets.created_at | date | Time asset was enrolled with Uptycs | 
| Uptycs.Assets.host_name | string | Hostname in Uptycs DB | 
| Uptycs.Assets.os | string | os installed on asset (Windows, Linux, Mac OS X) | 
| Uptycs.Assets.os_version | string | os version | 
| Uptycs.Assets.last_activity_at | date | Last activity | 
| Uptycs.Assets.deleted_at | date | Time asset was unenrolled from Uptycs | 
| Uptycs.Assets.osquery_version | string | Current version of osquery installed on the asset | 


##### Command Example
`uptycs-get-assets os="Mac OS X/Apple OS X/macOS" limit=1`

##### Context Example
```
{
    "Uptycs.Assets": [
        {
            "status": "active", 
            "last_enrolled_at": "2019-07-19 14:47:27.485", 
            "os_version": "10.14.5", 
            "osquery_version": "3.2.6.51-Uptycs", 
            "created_at": "2018-09-25 16:38:16.440", 
            "longitude": -97.822, 
            "os_flavor": "darwin", 
            "host_name": "kyle-mbp-work", 
            "latitude": 37.751, 
            "last_activity_at": "2019-07-19 17:02:41.704", 
            "os": "Mac OS X", 
            "id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "location": "United States"
        }
    ]
}
```

##### Human Readable Output
### Uptycs Assets
|id|host_name|os|os_version|osquery_version|last_activity_at|
|---|---|---|---|---|---|
|984d4a7a-9f3a-580a-a3ef-2841a561669b|kyle-mbp-work|Mac OS X|10.14.5|3.2.6.51-Uptycs|2019-07-19 17:02:41.704|


### 2. uptycs-run-query
---
enter a SQL query to run against your Uptycs database.  A list of tables can be found at osquery.io/schema, or by using the query "select * from information_schema.tables"
##### Base Command

`uptycs-run-query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | This is the query that will be run.  Queries should be written for a SQLite database. For example, "SELECT * FROM processes" returns the entire table named "processes".  | Required | 
| query_type | The query can be run globally (returns results for entire history stored in Uptycs DB) or real-time (returns results for queries run on endpoints at the time of query execution) | Required | 
| asset_id | *realtime queries only*  This argument should be used when one wants to run a realtime query on a particular asset. | Optional | 
| host_name_is | *realtime queries only*  Only return assets with this hostname | Optional | 
| host_name_like | *realtime queries only* . Only return assets with this string in the hostname. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.QueryResults | unknown | Results of executed query | 


##### Command Example
`uptycs-run-query query="SELECT * FROM process_open_sockets LIMIT 10" query_type=global host_name_like="uptycs-osquery-"`

##### Context Example
```
{
    "Uptycs.QueryResults": [
        {
            "protocol": 6, 
            "family": 2, 
            "upt_counter": 20595, 
            "pid": 11, 
            "upt_asset_id": "a4991bf9-13e3-026b-7b46-af192746d556", 
            "upt_hostname": "uptycs-osquery-d4trq", 
            "local_port": 45864, 
            "upt_asset_tags": null, 
            "upt_hash": "1752f1a2-f773-5812-b611-577ee662b889", 
            "state": "ESTABLISHED", 
            "upt_asset_group_id": null, 
            "upt_time": "2019-04-18 02:37:09.000", 
            "local_address": "10.8.0.29", 
            "upt_added": false, 
            "upt_server_time": null, 
            "remote_address": "18.213.163.112", 
            "fd": 14, 
            "upt_asset_group_name": null, 
            "path": "", 
            "upt_day": 20190418, 
            "socket": 127377813, 
            "upt_epoch": 0, 
            "remote_port": 443, 
            "net_namespace": "4026532943"
        }, 
        {
            "protocol": 6, 
            "family": 2, 
            "upt_counter": 20595, 
            "pid": 11, 
            "upt_asset_id": "a4991bf9-13e3-026b-7b46-af192746d556", 
            "upt_hostname": "uptycs-osquery-d4trq", 
            "local_port": 45864, 
            "upt_asset_tags": null, 
            "upt_hash": "70dce553-3bca-5701-834c-8f2b94afd8f3", 
            "state": "CLOSE_WAIT", 
            "upt_asset_group_id": null, 
            "upt_time": "2019-04-18 02:37:09.000", 
            "local_address": "10.8.0.29", 
            "upt_added": true, 
            "upt_server_time": null, 
            "remote_address": "18.213.163.112", 
            "fd": 14, 
            "upt_asset_group_name": null, 
            "path": "", 
            "upt_day": 20190418, 
            "socket": 127377813, 
            "upt_epoch": 0, 
            "remote_port": 443, 
            "net_namespace": "4026532943"
        }, 
        {
            "protocol": 6, 
            "family": 2, 
            "upt_counter": 1267, 
            "pid": 11, 
            "upt_asset_id": "a4991bf9-13e3-026b-7b46-af192746d556", 
            "upt_hostname": "uptycs-osquery-d4trq", 
            "local_port": 34164, 
            "upt_asset_tags": null, 
            "upt_hash": "f8d24a1b-15d5-5c41-9994-2f70920fdc39", 
            "state": "CLOSE_WAIT", 
            "upt_asset_group_id": null, 
            "upt_time": "2019-04-18 20:52:05.000", 
            "local_address": "10.8.0.29", 
            "upt_added": false, 
            "upt_server_time": null, 
            "remote_address": "18.213.163.112", 
            "fd": 14, 
            "upt_asset_group_name": null, 
            "path": "", 
            "upt_day": 20190418, 
            "socket": 128588161, 
            "upt_epoch": 0, 
            "remote_port": 443, 
            "net_namespace": "4026532943"
        }, 
        {
            "protocol": 6, 
            "family": 2, 
            "upt_counter": 1267, 
            "pid": 11, 
            "upt_asset_id": "a4991bf9-13e3-026b-7b46-af192746d556", 
            "upt_hostname": "uptycs-osquery-d4trq", 
            "local_port": 34754, 
            "upt_asset_tags": null, 
            "upt_hash": "0603bdcc-8e90-58d9-831e-8adb3ca35358", 
            "state": "ESTABLISHED", 
            "upt_asset_group_id": null, 
            "upt_time": "2019-04-18 20:52:05.000", 
            "local_address": "10.8.0.29", 
            "upt_added": true, 
            "upt_server_time": null, 
            "remote_address": "18.213.163.112", 
            "fd": 14, 
            "upt_asset_group_name": null, 
            "path": "", 
            "upt_day": 20190418, 
            "socket": 128594058, 
            "upt_epoch": 0, 
            "remote_port": 443, 
            "net_namespace": "4026532943"
        }, 
        {
            "protocol": 6, 
            "family": 2, 
            "upt_counter": 1024, 
            "pid": 2545, 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "upt_hostname": "kyle-mbp-work", 
            "local_port": 61925, 
            "upt_asset_tags": null, 
            "upt_hash": "754d2272-caf2-5d56-8638-984d7392e7f2", 
            "state": "ESTABLISHED", 
            "upt_asset_group_id": null, 
            "upt_time": "2019-04-18 15:26:49.000", 
            "local_address": "192.168.1.161", 
            "upt_added": false, 
            "upt_server_time": null, 
            "remote_address": "18.213.163.112", 
            "fd": 186, 
            "upt_asset_group_name": null, 
            "path": "", 
            "upt_day": 20190418, 
            "socket": 0, 
            "upt_epoch": 0, 
            "remote_port": 443, 
            "net_namespace": null
        }, 
        {
            "protocol": 6, 
            "family": 2, 
            "upt_counter": 1024, 
            "pid": 2545, 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "upt_hostname": "kyle-mbp-work", 
            "local_port": 61934, 
            "upt_asset_tags": null, 
            "upt_hash": "ce103524-0f5f-5aea-abad-b8529620b7bf", 
            "state": "ESTABLISHED", 
            "upt_asset_group_id": null, 
            "upt_time": "2019-04-18 15:26:49.000", 
            "local_address": "192.168.1.161", 
            "upt_added": false, 
            "upt_server_time": null, 
            "remote_address": "18.213.163.112", 
            "fd": 191, 
            "upt_asset_group_name": null, 
            "path": "", 
            "upt_day": 20190418, 
            "socket": 0, 
            "upt_epoch": 0, 
            "remote_port": 443, 
            "net_namespace": null
        }, 
        {
            "protocol": 6, 
            "family": 2, 
            "upt_counter": 1024, 
            "pid": 854, 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "upt_hostname": "kyle-mbp-work", 
            "local_port": 61573, 
            "upt_asset_tags": null, 
            "upt_hash": "c2f00244-9fa4-5c47-a49b-9bd0390d169f", 
            "state": "ESTABLISHED", 
            "upt_asset_group_id": null, 
            "upt_time": "2019-04-18 15:26:49.000", 
            "local_address": "192.168.1.161", 
            "upt_added": false, 
            "upt_server_time": null, 
            "remote_address": "149.96.6.118", 
            "fd": 33, 
            "upt_asset_group_name": null, 
            "path": "", 
            "upt_day": 20190418, 
            "socket": 0, 
            "upt_epoch": 0, 
            "remote_port": 443, 
            "net_namespace": null
        }, 
        {
            "protocol": 6, 
            "family": 2, 
            "upt_counter": 1024, 
            "pid": 2545, 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "upt_hostname": "kyle-mbp-work", 
            "local_port": 61919, 
            "upt_asset_tags": null, 
            "upt_hash": "0439a9f5-130d-5ff4-a8df-d72275e4b9e2", 
            "state": "ESTABLISHED", 
            "upt_asset_group_id": null, 
            "upt_time": "2019-04-18 15:26:49.000", 
            "local_address": "192.168.1.161", 
            "upt_added": false, 
            "upt_server_time": null, 
            "remote_address": "18.213.163.112", 
            "fd": 54, 
            "upt_asset_group_name": null, 
            "path": "", 
            "upt_day": 20190418, 
            "socket": 0, 
            "upt_epoch": 0, 
            "remote_port": 443, 
            "net_namespace": null
        }, 
        {
            "protocol": 6, 
            "family": 2, 
            "upt_counter": 1024, 
            "pid": 854, 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "upt_hostname": "kyle-mbp-work", 
            "local_port": 61573, 
            "upt_asset_tags": null, 
            "upt_hash": "fe0218c2-b337-5198-ac9c-a1f8784a2c08", 
            "state": "ESTABLISHED", 
            "upt_asset_group_id": null, 
            "upt_time": "2019-04-18 15:26:49.000", 
            "local_address": "192.168.1.161", 
            "upt_added": false, 
            "upt_server_time": null, 
            "remote_address": "149.96.6.118", 
            "fd": 62, 
            "upt_asset_group_name": null, 
            "path": "", 
            "upt_day": 20190418, 
            "socket": 0, 
            "upt_epoch": 0, 
            "remote_port": 443, 
            "net_namespace": null
        }, 
        {
            "protocol": 6, 
            "family": 2, 
            "upt_counter": 1024, 
            "pid": 854, 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "upt_hostname": "kyle-mbp-work", 
            "local_port": 61939, 
            "upt_asset_tags": null, 
            "upt_hash": "6194c89c-171c-55c8-9355-5b53a4a28a5a", 
            "state": "ESTABLISHED", 
            "upt_asset_group_id": null, 
            "upt_time": "2019-04-18 15:26:49.000", 
            "local_address": "192.168.1.161", 
            "upt_added": true, 
            "upt_server_time": null, 
            "remote_address": "149.96.6.118", 
            "fd": 7, 
            "upt_asset_group_name": null, 
            "path": "", 
            "upt_day": 20190418, 
            "socket": 0, 
            "upt_epoch": 0, 
            "remote_port": 443, 
            "net_namespace": null
        }
    ]
}
```

##### Human Readable Output
### Uptycs Query Result
|protocol|family|upt_counter|pid|upt_asset_id|upt_hostname|local_port|upt_asset_tags|upt_hash|upt_asset_group_id|state|upt_time|local_address|upt_added|upt_server_time|remote_address|fd|upt_asset_group_name|path|upt_day|socket|upt_epoch|remote_port|net_namespace|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|6|2|20595|11|a4991bf9-13e3-026b-7b46-af192746d556|uptycs-osquery-d4trq|45864||1752f1a2-f773-5812-b611-577ee662b889||ESTABLISHED|2019-04-18 02:37:09.000|10.8.0.29|false||18.213.163.112|14|||20190418|127377813|0|443|4026532943|
|6|2|20595|11|a4991bf9-13e3-026b-7b46-af192746d556|uptycs-osquery-d4trq|45864||70dce553-3bca-5701-834c-8f2b94afd8f3||CLOSE_WAIT|2019-04-18 02:37:09.000|10.8.0.29|true||18.213.163.112|14|||20190418|127377813|0|443|4026532943|
|6|2|1267|11|a4991bf9-13e3-026b-7b46-af192746d556|uptycs-osquery-d4trq|34164||f8d24a1b-15d5-5c41-9994-2f70920fdc39||CLOSE_WAIT|2019-04-18 20:52:05.000|10.8.0.29|false||18.213.163.112|14|||20190418|128588161|0|443|4026532943|
|6|2|1267|11|a4991bf9-13e3-026b-7b46-af192746d556|uptycs-osquery-d4trq|34754||0603bdcc-8e90-58d9-831e-8adb3ca35358||ESTABLISHED|2019-04-18 20:52:05.000|10.8.0.29|true||18.213.163.112|14|||20190418|128594058|0|443|4026532943|
|6|2|1024|2545|984d4a7a-9f3a-580a-a3ef-2841a561669b|kyle-mbp-work|61925||754d2272-caf2-5d56-8638-984d7392e7f2||ESTABLISHED|2019-04-18 15:26:49.000|192.168.1.161|false||18.213.163.112|186|||20190418|0|0|443||
|6|2|1024|2545|984d4a7a-9f3a-580a-a3ef-2841a561669b|kyle-mbp-work|61934||ce103524-0f5f-5aea-abad-b8529620b7bf||ESTABLISHED|2019-04-18 15:26:49.000|192.168.1.161|false||18.213.163.112|191|||20190418|0|0|443||
|6|2|1024|854|984d4a7a-9f3a-580a-a3ef-2841a561669b|kyle-mbp-work|61573||c2f00244-9fa4-5c47-a49b-9bd0390d169f||ESTABLISHED|2019-04-18 15:26:49.000|192.168.1.161|false||149.96.6.118|33|||20190418|0|0|443||
|6|2|1024|2545|984d4a7a-9f3a-580a-a3ef-2841a561669b|kyle-mbp-work|61919||0439a9f5-130d-5ff4-a8df-d72275e4b9e2||ESTABLISHED|2019-04-18 15:26:49.000|192.168.1.161|false||18.213.163.112|54|||20190418|0|0|443||
|6|2|1024|854|984d4a7a-9f3a-580a-a3ef-2841a561669b|kyle-mbp-work|61573||fe0218c2-b337-5198-ac9c-a1f8784a2c08||ESTABLISHED|2019-04-18 15:26:49.000|192.168.1.161|false||149.96.6.118|62|||20190418|0|0|443||
|6|2|1024|854|984d4a7a-9f3a-580a-a3ef-2841a561669b|kyle-mbp-work|61939||6194c89c-171c-55c8-9355-5b53a4a28a5a||ESTABLISHED|2019-04-18 15:26:49.000|192.168.1.161|true||149.96.6.118|7|||20190418|0|0|443||


### 3. uptycs-get-alerts
---
return alerts from Uptycs DB
##### Base Command

`uptycs-get-alerts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Unique Uptycs alert id which will retrieve a specific alert.  Use this argument without any other arguments. | Optional | 
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id", "host_name_is" or "host_name_like" at the same time. | Optional | 
| code | Alert code to specify which types of alerts you would like to retrieve | Optional | 
| host_name_is | Only return assets with this hostname.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| host_name_like | Only return assets with this string in the hostname.  Use this to find a selection of assets with similar hostnames.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 
| start_window | Beginning of window to search for open connections.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| end_window | End of window to search for open connections.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| time_ago | Specifies how far back you want to look.  Format examples: 2 hours, 4 minutes, 6 month, 1 day, etc. | Optional | 
| value | Varies for different alerts.  For example, a Bad IP alert would have the IP address as the value.  A program crash alert would have the name of the program which crashed as the value. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Alerts.description | string | Description of alert | 
| Uptycs.Alerts.upt_asset_id | string | Uptycs asset ID | 
| Uptycs.Alerts.code | string | Alert code in Uptycs DB | 
| Uptycs.Alerts.severity | string | The severity of the alert | 
| Uptycs.Alerts.alert_time | date | Time alert was created at | 
| Uptycs.Alerts.value | string | Specific problem which caused an alert.  It may be an IP address, a program that crashed, a file with a file hash known to be malware, etc. | 
| Uptycs.Alerts.host_name | string | Hostname for the asset which fired the alert | 
| Uptycs.Alerts.id | string | unique Uptycs id for a particular alert | 
| Uptycs.Alerts.threat_indicator_id | string | unique Uptycs id that identifies the threat indicator which triggered this alert | 
| Uptycs.Alerts.threat_source_name | string | name of the source of the threat indicator that triggered this alert | 
| Uptycs.Alerts.pid | number | pid of the process which was responsible for firing the alert | 


##### Command Example
`uptycs-get-alerts limit=1 time_ago="30 days"`

##### Context Example
```
{
    "Uptycs.Alerts": [
        {
            "status": "open", 
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "threat_source_name": "No threat source for                     this alert", 
            "severity": "medium", 
            "created_at": "2019-07-02 11:41:25.915", 
            "pid": 437, 
            "updated_at": "2019-07-02 11:41:25.915", 
            "value": "Amazon Music Helper", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "threat_indicator_id": "No threat indicator                     for this alert", 
            "alert_time": "2019-07-02 11:41:22.000", 
            "host_name": "kyle-mbp-work", 
            "key": "identifier", 
            "assigned_to": null, 
            "metadata": "{\"type\":\"application\",\"pid\":437,\"path\":\"/Applications/Amazon Music.app/Contents/MacOS/Amazon Music Helper\",\"crash_path\":\"/Library/Logs/DiagnosticReports/Amazon Music Helper_2019-06-02-103630_Kyles-MacBook-Pro.crash\",\"parent\":1,\"responsible\":\"Amazon Music Helper [437]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\",\"identifier\":\"Amazon Music Helper\"}", 
            "id": "0049641c-1645-4b98-830f-7f1ce783bfcc", 
            "grouping": "OS X Crashes"
        }
    ]
}
```

##### Human Readable Output
### Uptycs Alerts: 
|upt_asset_id|host_name|grouping|alert_time|description|value|severity|threat_indicator_id|threat_source_name|
|---|---|---|---|---|---|---|---|---|
|984d4a7a-9f3a-580a-a3ef-2841a561669b|kyle-mbp-work|OS X Crashes|2019-07-02 11:41:22.000|Crash|Amazon Music Helper|medium|No threat indicator                     for this alert|No threat source for                     this alert|


### 4. uptycs-get-alert-rules
---
retrieve a list of alert rules
##### Base Command

`uptycs-get-alert-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-get-alert-rules limit=1`

##### Context Example
```

```

##### Human Readable Output
### Uptycs Alert Rules
|name|description|grouping|enabled|updatedAt|code|
|---|---|---|---|---|---|
|Bad Domain Alert|Bad Domain Alert|Bad Domain|true|2019-06-19T08:17:04.892Z|BAD_DOMAIN|


### 5. uptycs-get-event-rules
---
retrieve a list of event rules
##### Base Command

`uptycs-get-event-rules`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-get-event-rules limit=1`

##### Context Example
```

```

##### Human Readable Output
### Uptycs Event Rules
|name|description|grouping|enabled|updatedAt|code|
|---|---|---|---|---|---|
|Bad domain|Malicious domain resolved|default|true|2019-06-19T08:17:05.115Z|BAD_DOMAIN|


### 6. uptycs-get-events
---
return events from Uptycs DB
##### Base Command

`uptycs-get-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id", "host_name_is" or "host_name_like" at the same time. | Optional | 
| code | Event code to specify which types of events you would like to retrieve | Optional | 
| host_name_is | Only return assets with this hostname.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| host_name_like | Only return assets with this string in the hostname.  Use this to find a selection of assets with similar hostnames.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 
| start_window | Beginning of window to search for open connections.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| end_window | End of window to search for open connections.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| time_ago | Specifies how far back you want to look.  Format examples: 2 hours, 4 minutes, 6 month, 1 day, etc. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Events.description | string | Description of event | 
| Uptycs.Events.asset_id | string | Uptycs asset ID | 
| Uptycs.Events.code | string | Event code in Uptycs DB | 
| Uptycs.Events.created_at | date | Time event was created at | 
| Uptycs.Events.id | string | Uptycs event id for this particular event | 
| Uptycs.Events.host_name | string | Hostname for the assets this event occurred on | 
| Uptycs.Events.grouping | string | Group that this event belongs to | 
| Uptycs.Events.value | string | The value will be different for different types of events.  It is that which triggered the event.  For example, a Bad IP connection will have the IP address here, and a program crash will have the name of the program that crashed here. | 
| Uptycs.Events.severity | string | The severity of the event | 


##### Command Example
`uptycs-get-events limit=10 time_ago="30 days"`

##### Context Example
```
{
    "Uptycs.Events": [
        {
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "event_time": "2019-07-07 13:03:11.000", 
            "severity": "medium", 
            "created_at": "2019-07-07 13:03:16.000", 
            "value": "mediaremoted", 
            "upt_asset_id": "a9bf504c-6bdc-5e56-8c8e-efeec2b1497d", 
            "host_name": "brandons-mini.fios-router.home", 
            "key": "identifier", 
            "metadata": "{\"type\":\"application\",\"pid\":11895,\"path\":\"/System/Library/PrivateFrameworks/MediaRemote.framework/Support/mediaremoted\",\"crash_path\":\"/Library/Logs/DiagnosticReports/mediaremoted_2019-06-09-101301_Brandons-Mac-mini.crash\",\"parent\":1,\"responsible\":\"mediaremoted [11895]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\"}", 
            "id": "8c99676b-02b6-4806-a1d8-a8dff3c55d1e", 
            "grouping": "OS X Crashes"
        }, 
        {
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "event_time": "2019-07-02 11:41:22.000", 
            "severity": "medium", 
            "created_at": "2019-07-02 11:41:25.000", 
            "value": "Amazon Music Helper", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "host_name": "kyle-mbp-work", 
            "key": "identifier", 
            "metadata": "{\"type\":\"application\",\"pid\":437,\"path\":\"/Applications/Amazon Music.app/Contents/MacOS/Amazon Music Helper\",\"crash_path\":\"/Library/Logs/DiagnosticReports/Amazon Music Helper_2019-06-02-103630_Kyles-MacBook-Pro.crash\",\"parent\":1,\"responsible\":\"Amazon Music Helper [437]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\"}", 
            "id": "19237e6f-b5b4-4ec7-b0dc-6b6b011f1038", 
            "grouping": "OS X Crashes"
        }, 
        {
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "event_time": "2019-06-27 09:26:25.000", 
            "severity": "medium", 
            "created_at": "2019-06-27 09:26:31.000", 
            "value": "Amazon Music Helper", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "host_name": "kyle-mbp-work", 
            "key": "identifier", 
            "metadata": "{\"type\":\"application\",\"pid\":437,\"path\":\"/Applications/Amazon Music.app/Contents/MacOS/Amazon Music Helper\",\"crash_path\":\"/Library/Logs/DiagnosticReports/Amazon Music Helper_2019-06-02-103630_Kyles-MacBook-Pro.crash\",\"parent\":1,\"responsible\":\"Amazon Music Helper [437]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\"}", 
            "id": "7d9e815a-4739-4608-936f-f0cfa5968e3d", 
            "grouping": "OS X Crashes"
        }, 
        {
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "event_time": "2019-06-27 09:26:25.000", 
            "severity": "medium", 
            "created_at": "2019-06-27 09:26:31.000", 
            "value": "osqueryd", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "host_name": "kyle-mbp-work", 
            "key": "identifier", 
            "metadata": "{\"type\":\"application\",\"pid\":11602,\"path\":\"/usr/local/bin/osqueryd\",\"crash_path\":\"/Library/Logs/DiagnosticReports/osqueryd_2019-05-27-195843_Kyles-MacBook-Pro.crash\",\"parent\":11596,\"responsible\":\"osqueryd [11602]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\"}", 
            "id": "d066187e-18a7-4ff1-8e9a-7e87346391dc", 
            "grouping": "OS X Crashes"
        }, 
        {
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "event_time": "2019-06-27 00:08:17.000", 
            "severity": "medium", 
            "created_at": "2019-06-27 00:08:22.000", 
            "value": "mediaremoted", 
            "upt_asset_id": "a9bf504c-6bdc-5e56-8c8e-efeec2b1497d", 
            "host_name": "brandons-mini.fios-router.home", 
            "key": "identifier", 
            "metadata": "{\"type\":\"application\",\"pid\":11895,\"path\":\"/System/Library/PrivateFrameworks/MediaRemote.framework/Support/mediaremoted\",\"crash_path\":\"/Library/Logs/DiagnosticReports/mediaremoted_2019-06-09-101301_Brandons-Mac-mini.crash\",\"parent\":1,\"responsible\":\"mediaremoted [11895]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\"}", 
            "id": "c3838f00-2358-46ef-a558-4417cce2e59e", 
            "grouping": "OS X Crashes"
        }, 
        {
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "event_time": "2019-06-25 15:19:08.000", 
            "severity": "medium", 
            "created_at": "2019-06-25 15:19:22.000", 
            "value": "Amazon Music Helper", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "host_name": "kyle-mbp-work", 
            "key": "identifier", 
            "metadata": "{\"type\":\"application\",\"pid\":437,\"path\":\"/Applications/Amazon Music.app/Contents/MacOS/Amazon Music Helper\",\"crash_path\":\"/Library/Logs/DiagnosticReports/Amazon Music Helper_2019-06-02-103630_Kyles-MacBook-Pro.crash\",\"parent\":1,\"responsible\":\"Amazon Music Helper [437]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\"}", 
            "id": "7e1a3764-31ed-49cc-9cd0-23159d3d40c0", 
            "grouping": "OS X Crashes"
        }, 
        {
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "event_time": "2019-06-25 15:19:08.000", 
            "severity": "medium", 
            "created_at": "2019-06-25 15:19:22.000", 
            "value": "osqueryd", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "host_name": "kyle-mbp-work", 
            "key": "identifier", 
            "metadata": "{\"type\":\"application\",\"pid\":11602,\"path\":\"/usr/local/bin/osqueryd\",\"crash_path\":\"/Library/Logs/DiagnosticReports/osqueryd_2019-05-27-195843_Kyles-MacBook-Pro.crash\",\"parent\":11596,\"responsible\":\"osqueryd [11602]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\"}", 
            "id": "6ece8d0b-7498-46e5-b8f0-d14773c96aa2", 
            "grouping": "OS X Crashes"
        }, 
        {
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "event_time": "2019-06-24 19:25:30.000", 
            "severity": "medium", 
            "created_at": "2019-06-24 19:25:35.000", 
            "value": "mediaremoted", 
            "upt_asset_id": "a9bf504c-6bdc-5e56-8c8e-efeec2b1497d", 
            "host_name": "brandons-mini.fios-router.home", 
            "key": "identifier", 
            "metadata": "{\"type\":\"application\",\"pid\":11895,\"path\":\"/System/Library/PrivateFrameworks/MediaRemote.framework/Support/mediaremoted\",\"crash_path\":\"/Library/Logs/DiagnosticReports/mediaremoted_2019-06-09-101301_Brandons-Mac-mini.crash\",\"parent\":1,\"responsible\":\"mediaremoted [11895]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\"}", 
            "id": "8c14a1a5-0f86-4a50-a4ca-973a83003482", 
            "grouping": "OS X Crashes"
        }, 
        {
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "event_time": "2019-06-23 22:23:49.000", 
            "severity": "medium", 
            "created_at": "2019-06-23 22:23:51.000", 
            "value": "Amazon Music Helper", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "host_name": "kyle-mbp-work", 
            "key": "identifier", 
            "metadata": "{\"type\":\"application\",\"pid\":437,\"path\":\"/Applications/Amazon Music.app/Contents/MacOS/Amazon Music Helper\",\"crash_path\":\"/Library/Logs/DiagnosticReports/Amazon Music Helper_2019-06-02-103630_Kyles-MacBook-Pro.crash\",\"parent\":1,\"responsible\":\"Amazon Music Helper [437]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\"}", 
            "id": "26464fa2-6dc2-4e01-9b0f-f7d57b9d1b3d", 
            "grouping": "OS X Crashes"
        }, 
        {
            "code": "OSX_CRASHES", 
            "description": "Crash", 
            "event_time": "2019-06-23 22:23:49.000", 
            "severity": "medium", 
            "created_at": "2019-06-23 22:23:51.000", 
            "value": "osqueryd", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "host_name": "kyle-mbp-work", 
            "key": "identifier", 
            "metadata": "{\"type\":\"application\",\"pid\":11602,\"path\":\"/usr/local/bin/osqueryd\",\"crash_path\":\"/Library/Logs/DiagnosticReports/osqueryd_2019-05-27-195843_Kyles-MacBook-Pro.crash\",\"parent\":11596,\"responsible\":\"osqueryd [11602]\",\"exception_type\":\"EXC_BAD_ACCESS (SIGSEGV)\"}", 
            "id": "3a0f7ef8-9c3e-4267-8fbc-cc148e0edc9b", 
            "grouping": "OS X Crashes"
        }
    ]
}
```

##### Human Readable Output
### Uptycs Events
|host_name|grouping|event_time|description|value|severity|
|---|---|---|---|---|---|
|brandons-mini.fios-router.home|OS X Crashes|2019-07-07 13:03:11.000|Crash|mediaremoted|medium|
|kyle-mbp-work|OS X Crashes|2019-07-02 11:41:22.000|Crash|Amazon Music Helper|medium|
|kyle-mbp-work|OS X Crashes|2019-06-27 09:26:25.000|Crash|Amazon Music Helper|medium|
|kyle-mbp-work|OS X Crashes|2019-06-27 09:26:25.000|Crash|osqueryd|medium|
|brandons-mini.fios-router.home|OS X Crashes|2019-06-27 00:08:17.000|Crash|mediaremoted|medium|
|kyle-mbp-work|OS X Crashes|2019-06-25 15:19:08.000|Crash|Amazon Music Helper|medium|
|kyle-mbp-work|OS X Crashes|2019-06-25 15:19:08.000|Crash|osqueryd|medium|
|brandons-mini.fios-router.home|OS X Crashes|2019-06-24 19:25:30.000|Crash|mediaremoted|medium|
|kyle-mbp-work|OS X Crashes|2019-06-23 22:23:49.000|Crash|Amazon Music Helper|medium|
|kyle-mbp-work|OS X Crashes|2019-06-23 22:23:49.000|Crash|osqueryd|medium|


### 7. uptycs-get-process-open-sockets
---
find processes which opened a socket
##### Base Command

`uptycs-get-process-open-sockets`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id", "host_name_is" or "host_name_like" at the same time. | Optional | 
| host_name_is | Only return assets with this hostname.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| host_name_like | Only return assets with this string in the hostname.  Use this to find a selection of assets with similar hostnames.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| ip | IP address which process opened a socket to. | Optional | 
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 
| start_window | Beginning of window to search for open sockets.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| end_window | End of window to search for open sockets.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| time | Exact time at which the socket was opened. | Optional | 
| time_ago | Specifies how far back you want to look.  Format examples: 2 hours, 4 minutes, 6 month, 1 day, etc. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Sockets.pid | number | pid of process which opened a connection to a specified IP | 
| Uptycs.Sockets.upt_hostname | string | hostname of the asset which ran the specified process | 
| Uptycs.Sockets.upt_time | date | time at which the connection was opened | 
| Uptycs.Sockets.path | string | file path to the process being run | 
| Uptycs.Sockets.local_address | string | local IP for specified connection | 
| Uptycs.Sockets.remote_address | string | remote IP for specified connection | 
| Uptycs.Sockets.local_port | number | local port for specified connection | 
| Uptycs.Sockets.remote_port | number | remote port for specified connection | 
| Uptycs.Sockets.upt_asset_id | string | asset id for asset which ran the specified process | 
| Uptycs.Sockets.socket | number | socket used to open the connection | 
| Uptycs.Sockets.family | number | network protocol | 
| Uptycs.Sockets.state | string | state of the connection | 
| Uptycs.Sockets.protocol | number | transport protocol | 


##### Command Example
`uptycs-get-process-open-sockets limit=1`

##### Context Example
```
{
    "Uptycs.Sockets": [
        {
            "protocol": 6, 
            "socket": 0, 
            "family": 2, 
            "local_port": 54755, 
            "remote_port": 443, 
            "pid": 704, 
            "remote_address": "69.147.92.12", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "upt_time": "2019-07-19 17:03:31.000", 
            "state": "ESTABLISHED", 
            "upt_hostname": "kyle-mbp-work", 
            "path": null, 
            "local_address": "192.168.86.61"
        }
    ]
}
```

##### Human Readable Output
### process_open_sockets
|upt_hostname|pid|local_address|remote_address|upt_time|local_port|remote_port|socket|
|---|---|---|---|---|---|---|---|
|kyle-mbp-work|704|192.168.86.61|69.147.92.12|2019-07-19 17:03:31.000|54755|443|0|


### 8. uptycs-get-process-information
---
get information for a particular process
##### Base Command

`uptycs-get-process-information`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id" and "host_name_is" at the same time. | Optional | 
| host_name_is | Hostname for asset which spawned the specified process. | Optional | 
| pid | pid for the process. | Required | 
| time | Time that the specified process was spawned. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Proc.pid | number | pid for the process | 
| Uptycs.Proc.upt_hostname | string | hostname for asset which spawned the specified process | 
| Uptycs.Proc.upt_asset_id | string | asset id for asset which spawned the specified process | 
| Uptycs.Proc.parent | number | pid for the parent process | 
| Uptycs.Proc.upt_add_time | date | time that the process was spawned | 
| Uptycs.Proc.upt_remove_time | date | time that the process was removed | 
| Uptycs.Proc.path | string | path to the process binary | 
| Uptycs.Proc.name | string | name of the process | 
| Uptycs.Proc.cmdline | string | complete argv of the process | 
| Uptycs.Proc.pgroup | number | process group | 
| Uptycs.Proc.cwd | string | process current working directory | 


##### Command Example
`uptycs-get-process-information asset_id="984d4a7a-9f3a-580a-a3ef-2841a561669b" pid=5119 time="2019-01-29 17:05:07.000"`

##### Context Example
```
{
    "Uptycs.Proc": [
        {
            "name": "VBoxHeadless", 
            "parent": 484, 
            "upt_add_time": "2019-01-29 16:14:27.000", 
            "pid": 5119, 
            "upt_remove_time": "2019-01-29 19:21:31.000 UTC", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless --comment vagrant_default_1535385658307_92120 --startvm 11742093-a8fa-4189-a88c-afc4cb7c70a6 --vrde config", 
            "upt_hostname": "kyle-mbp-work", 
            "pgroup": 5119, 
            "path": "/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless", 
            "cwd": "/Applications", 
            "upt_day": 20190129
        }
    ]
}
```

##### Human Readable Output
### Process information
|upt_hostname|parent|pid|name|path|cmdline|
|---|---|---|---|---|---|
|kyle-mbp-work|484|5119|VBoxHeadless|/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless|/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless --comment vagrant_default_1535385658307_92120 --startvm 11742093-a8fa-4189-a88c-afc4cb7c70a6 --vrde config|


### 9. uptycs-get-process-child-processes
---
get all the child processes for a given parent process
##### Base Command

`uptycs-get-process-child-processes`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset_id.  Do not use arguments "asset_id" and "host_name_is" at the same time. | Optional | 
| host_name_is | hostname for the asset which executed these processes. | Optional | 
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 
| parent | The pid for which all child processes will be found | Required | 
| parent_start_time | time at which the parent process was spawned | Required | 
| parent_end_time | time at which the parent process was killed, if it exists. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Children.pid | number | pid of a child process | 
| Uptycs.Children.upt_asset_id | string | asset id for asset which this process was run on | 
| Uptycs.Children.upt_hostname | string | hostname for asset which spawned the specified process | 
| Uptycs.Children.upt_add_time | date | time that the process was spawned | 
| Uptycs.Children.upt_remove_time | date | time that the process was removed | 
| Uptycs.Children.path | string | path to the process binary | 
| Uptycs.Children.parent | number | parent pid | 
| Uptycs.Children.name | string | name of the process | 
| Uptycs.Children.cmdline | string | complete argv for the process | 
| Uptycs.Children.pgroup | number | process group | 
| Uptycs.Children.cwd | string | process current working directory | 


##### Command Example
`uptycs-get-process-child-processes asset_id="984d4a7a-9f3a-580a-a3ef-2841a561669b" parent=484 parent_start_time="2019-01-28 14:16:58.000" parent_end_time="2019-01-29 19:21:31.000"`

##### Context Example
```
{
    "Uptycs.Children": [
        {
            "name": "VBoxHeadless", 
            "parent": 484, 
            "upt_add_time": "2019-01-29 16:14:27.000", 
            "pid": 5119, 
            "upt_remove_time": "2019-01-29 19:21:31.000 UTC", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless --comment vagrant_default_1535385658307_92120 --startvm 11742093-a8fa-4189-a88c-afc4cb7c70a6 --vrde config", 
            "upt_hostname": "kyle-mbp-work", 
            "pgroup": 5119, 
            "path": "/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless", 
            "cwd": "/Applications", 
            "upt_day": 20190129
        }, 
        {
            "name": "VirtualBoxVM", 
            "parent": 484, 
            "upt_add_time": "2019-01-29 16:00:17.000", 
            "pid": 5008, 
            "upt_remove_time": "2019-01-29 16:13:55.000 UTC", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "/Applications/VirtualBox.app/Contents/Resources/VirtualBoxVM.app/Contents/MacOS/VirtualBoxVM --comment vagrant_default_1535385658307_92120 --startvm 11742093-a8fa-4189-a88c-afc4cb7c70a6 --no-startvm-errormsgbox", 
            "upt_hostname": "kyle-mbp-work", 
            "pgroup": 5008, 
            "path": "/Applications/VirtualBox.app/Contents/MacOS/VirtualBoxVM", 
            "cwd": "/Applications", 
            "upt_day": 20190129
        }, 
        {
            "name": "VirtualBoxVM", 
            "parent": 484, 
            "upt_add_time": "2019-01-29 15:58:10.000", 
            "pid": 5002, 
            "upt_remove_time": "2019-01-29 16:00:17.000 UTC", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "/Applications/VirtualBox.app/Contents/Resources/VirtualBoxVM.app/Contents/MacOS/VirtualBoxVM --comment basevm_centos_7_orig --startvm 58264539-0e7a-418f-91be-365aa0f20854 --no-startvm-errormsgbox", 
            "upt_hostname": "kyle-mbp-work", 
            "pgroup": 5002, 
            "path": "/Applications/VirtualBox.app/Contents/MacOS/VirtualBoxVM", 
            "cwd": "/Applications", 
            "upt_day": 20190129
        }, 
        {
            "name": "VirtualBoxVM", 
            "parent": 484, 
            "upt_add_time": "2019-01-29 15:55:32.000", 
            "pid": 4994, 
            "upt_remove_time": "2019-01-29 15:57:38.000 UTC", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "/Applications/VirtualBox.app/Contents/Resources/VirtualBoxVM.app/Contents/MacOS/VirtualBoxVM --comment vagrant_default_1535385658307_92120 --startvm 11742093-a8fa-4189-a88c-afc4cb7c70a6 --no-startvm-errormsgbox", 
            "upt_hostname": "kyle-mbp-work", 
            "pgroup": 4994, 
            "path": "/Applications/VirtualBox.app/Contents/MacOS/VirtualBoxVM", 
            "cwd": "/Applications", 
            "upt_day": 20190129
        }, 
        {
            "name": "VirtualBoxVM", 
            "parent": 484, 
            "upt_add_time": "2019-01-28 17:00:39.000", 
            "pid": 3448, 
            "upt_remove_time": "2019-01-28 22:27:17.000 UTC", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "/Applications/VirtualBox.app/Contents/Resources/VirtualBoxVM.app/Contents/MacOS/VirtualBoxVM --comment ova-31822- --startvm d7414d11-5764-4583-aeb6-94e5527c851c --no-startvm-errormsgbox", 
            "upt_hostname": "kyle-mbp-work", 
            "pgroup": 3448, 
            "path": "/Applications/VirtualBox.app/Contents/MacOS/VirtualBoxVM", 
            "cwd": "/Applications", 
            "upt_day": 20190128
        }
    ]
}
```

##### Human Readable Output
### Child processes of a specified pid
|upt_hostname|pid|name|path|cmdline|upt_add_time|
|---|---|---|---|---|---|
|kyle-mbp-work|5119|VBoxHeadless|/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless|/Applications/VirtualBox.app/Contents/MacOS/VBoxHeadless --comment vagrant_default_1535385658307_92120 --startvm 11742093-a8fa-4189-a88c-afc4cb7c70a6 --vrde config|2019-01-29 16:14:27.000|
|kyle-mbp-work|5008|VirtualBoxVM|/Applications/VirtualBox.app/Contents/MacOS/VirtualBoxVM|/Applications/VirtualBox.app/Contents/Resources/VirtualBoxVM.app/Contents/MacOS/VirtualBoxVM --comment vagrant_default_1535385658307_92120 --startvm 11742093-a8fa-4189-a88c-afc4cb7c70a6 --no-startvm-errormsgbox|2019-01-29 16:00:17.000|
|kyle-mbp-work|5002|VirtualBoxVM|/Applications/VirtualBox.app/Contents/MacOS/VirtualBoxVM|/Applications/VirtualBox.app/Contents/Resources/VirtualBoxVM.app/Contents/MacOS/VirtualBoxVM --comment basevm_centos_7_orig --startvm 58264539-0e7a-418f-91be-365aa0f20854 --no-startvm-errormsgbox|2019-01-29 15:58:10.000|
|kyle-mbp-work|4994|VirtualBoxVM|/Applications/VirtualBox.app/Contents/MacOS/VirtualBoxVM|/Applications/VirtualBox.app/Contents/Resources/VirtualBoxVM.app/Contents/MacOS/VirtualBoxVM --comment vagrant_default_1535385658307_92120 --startvm 11742093-a8fa-4189-a88c-afc4cb7c70a6 --no-startvm-errormsgbox|2019-01-29 15:55:32.000|
|kyle-mbp-work|3448|VirtualBoxVM|/Applications/VirtualBox.app/Contents/MacOS/VirtualBoxVM|/Applications/VirtualBox.app/Contents/Resources/VirtualBoxVM.app/Contents/MacOS/VirtualBoxVM --comment ova-31822- --startvm d7414d11-5764-4583-aeb6-94e5527c851c --no-startvm-errormsgbox|2019-01-28 17:00:39.000|


### 10. uptycs-get-processes
---
find processes which are running or have run on a registered Uptycs asset
##### Base Command

`uptycs-get-processes`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id", "host_name_is" or "host_name_like" at the same time. | Optional | 
| host_name_is | Only return assets with this hostname.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| host_name_like | Only return assets with this string in the hostname.  Use this to find a selection of assets with similar hostnames.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 
| start_window | Beginning of window to search for open connections.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| end_window | End of window to search for open connections.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| time | Exact time at which the process was spawned. | Optional | 
| time_ago | Specifies how far back you want to look.  Format examples: 2 hours, 4 minutes, 6 month, 1 day, etc. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Process.pid | number | pid for a particular process | 
| Uptycs.Process.parent | number | pid for the parent of a particular process | 
| Uptycs.Process.upt_asset_id | string | uptycs asset id for the asset which is running (or ran) the process | 
| Uptycs.Process.upt_hostname | string | host name for the asset which is running (or ran) the process | 
| Uptycs.Process.upt_time | date | time at which the process was spawned | 
| Uptycs.Process.name | string | name of the process | 
| Uptycs.Process.path | string | path to the process binary | 
| Uptycs.Process.cmdline | string | comeplete argv for the process | 
| Uptycs.Process.pgroup | number | process group | 
| Uptycs.Process.cwd | string | process current working directory | 


##### Command Example
`uptycs-get-processes limit=1`

##### Context Example
```
{
    "Uptycs.Process": [
        {
            "name": "SCHelper", 
            "parent": 1, 
            "upt_time": "2019-07-19 07:29:32.000", 
            "pid": 60051, 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper", 
            "upt_hostname": "kyle-mbp-work", 
            "pgroup": 60051, 
            "path": "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper", 
            "cwd": "/"
        }
    ]
}
```

##### Human Readable Output
### Processes
|upt_hostname|pid|name|path|upt_time|parent|cmdline|
|---|---|---|---|---|---|---|
|kyle-mbp-work|60051|SCHelper|/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper|2019-07-19 07:29:32.000|1|/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/Helpers/SCHelper|


### 11. uptycs-get-process-open-files
---
find processes which have opened files
##### Base Command

`uptycs-get-process-open-files`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id", "host_name_is" or "host_name_like" at the same time. | Optional | 
| host_name_is | Only return assets with this hostname.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| host_name_like | Only return assets with this string in the hostname.  Use this to find a selection of assets with similar hostnames.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 
| start_window | Beginning of window to search for open connections.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| end_window | End of window to search for open connections.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| time | Exact time at which the process was spawned. | Optional | 
| time_ago | Specifies how far back you want to look.  Format examples: 2 hours, 4 minutes, 6 month, 1 day, etc. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Files.pid | number | pid for the process which opened a file | 
| Uptycs.Files.fd | number | process specific file descriptor number | 
| Uptycs.Files.upt_asset_id | string | Uptycs asset id for the the asset on which the file was opened | 
| Uptycs.Files.upt_hostname | string | Host name for the asset on which the file was opened | 
| Uptycs.Files.upt_time | date | time at which the file was opened | 
| Uptycs.Files.path | string | filesystem path of the file descriptor | 


##### Command Example
`uptycs-get-process-open-files limit=1`

##### Context Example
```
{
    "Uptycs.Files": [
        {
            "pid": 30143, 
            "upt_asset_id": "a4991bf9-13e3-026b-7b46-af192746d556", 
            "upt_hostname": "uptycs-osquery-mhntm", 
            "fd": 35, 
            "upt_time": "2019-07-19 17:00:38.000", 
            "path": "/var/osquery/osquery.db/001951.log"
        }
    ]
}
```

##### Human Readable Output
### Process which has opened a file
|upt_hostname|pid|path|fd|upt_time|
|---|---|---|---|---|
|uptycs-osquery-mhntm|30143|/var/osquery/osquery.db/001951.log|35|2019-07-19 17:00:38.000|


### 12. uptycs-set-alert-status
---
Set the status of an alert to new, assigned, resolved, or closed
##### Base Command

`uptycs-set-alert-status`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Uptycs alert id used to identify a particular alert | Required | 
| status | Status of the alert can be new, assigned, resolved, or closed | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-set-alert-status alert_id="9cb18abd-2c9a-43a8-988a-0601e9140f6c" status=assigned`

##### Context Example
```
{
    "Uptycs.AlertStatus": {
        "status": "assigned", 
        "code": "OUTBOUND_CONNECTION_TO_THREAT_IOC", 
        "updatedAt": "2019-07-19T17:07:27.447Z", 
        "updatedByEmail": "goo@test.com", 
        "updatedByAdmin": true, 
        "updatedBy": "B schmoll", 
        "id": "9cb18abd-2c9a-43a8-988a-0601e9140f6c", 
        "createdAt": "2019-02-22T21:13:21.238Z"
    }
}
```

##### Human Readable Output
### Uptycs Alert Status
|id|code|status|createdAt|updatedAt|
|---|---|---|---|---|
|9cb18abd-2c9a-43a8-988a-0601e9140f6c|OUTBOUND_CONNECTION_TO_THREAT_IOC|assigned|2019-02-22T21:13:21.238Z|2019-07-19T17:07:27.447Z|


### 13. uptycs-set-asset-tag
---
Sets a tag on a particular asset
##### Base Command

`uptycs-set-asset-tag`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Uptycs asset id for the asset that the tag should be set on | Required | 
| tag_key | Tag key that will be set on the asset | Required | 
| tag_value | Tag value that will be set on the asset | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-set-asset-tag asset_id="984d4a7a-9f3a-580a-a3ef-2841a561669b" tag_key="Uptycs" tag_value="work laptop"`

##### Context Example
```
{
    "Uptycs.AssetTags": {
        "hostName": "kyle-mbp-work", 
        "tags": [
            "Uptycs=work laptop", 
            "owner=Uptycs office", 
            "network=low", 
            "cpu=unknown", 
            "memory=unknown", 
            "disk=high"
        ]
    }
}
```

##### Human Readable Output
### Uptycs Asset Tag
|hostName|tags|
|---|---|
|kyle-mbp-work|Uptycs=work laptop,<br/>owner=Uptycs office,<br/>network=low,<br/>cpu=unknown,<br/>memory=unknown,<br/>disk=high|


### 14. uptycs-get-user-information
---
get info for an Uptycs user
##### Base Command

`uptycs-get-user-information`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Unique Uptycs id for the user | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.UserInfo.id | string | unique Uptycs id for the user | 
| Uptycs.UserInfo.name | string | Uptycs user's name | 
| Uptycs.UserInfo.email | string | Uptycs user's email address | 


##### Command Example
`uptycs-get-user-information user_id="33436e24-f30f-42d0-8438-d948be12b5af"`

##### Context Example
```
{
    "Uptycs.UserInfo": {
        "userObjectGroups": [
            {
                "userId": "33436e24-f30f-42d0-8438-d948be12b5af", 
                "updatedBy": null, 
                "objectGroupId": "106eef5e-c3a6-44eb-bb3d-1a2087cded3d", 
                "customerId": "e8213ef3-ef92-460e-a542-46dccd700c16", 
                "object_group_id": "106eef5e-c3a6-44eb-bb3d-1a2087cded3d", 
                "createdBy": null, 
                "updatedAt": "2018-09-24T17:24:45.606Z", 
                "id": "e10d6fbb-366c-4b89-86b3-89a1cd4ee83c", 
                "createdAt": "2018-09-24T17:24:45.606Z"
            }
        ], 
        "userRoles": {
            "admin": {
                "description": "Default admin role", 
                "updatedBy": null, 
                "custom": false, 
                "createdBy": null, 
                "updatedAt": "2019-06-19T08:15:49.286Z", 
                "id": "01b8ce5d-c93a-41a6-ba63-2e26c7d2cd79", 
                "hidden": false, 
                "permissions": [
                    "ALERT:READ", 
                    "ALERT_RULE:READ", 
                    "ASSET:READ", 
                    "CUSTOMER:READ", 
                    "DESTINATION:READ", 
                    "EVENT:READ", 
                    "EVENT_RULE:READ", 
                    "EXCEPTION:READ", 
                    "FIM:READ", 
                    "FLAG:READ", 
                    "OBJECT_GROUP:READ", 
                    "PROFILE:READ", 
                    "PROMETHEUS_TARGET:READ", 
                    "QUERY:READ", 
                    "QUERY_PACK:READ", 
                    "REPORT:READ", 
                    "REPORT_RUN:READ", 
                    "SCHEMA:READ", 
                    "SCHEDULED_GROUP:READ", 
                    "SCHEDULED_QUERY:READ", 
                    "SNAPSHOT:READ", 
                    "TAG:READ", 
                    "TAG_RULE:READ", 
                    "TEMPLATE:READ", 
                    "THREAT:READ", 
                    "USER:READ", 
                    "USER_ROLE:READ", 
                    "CURRENT_USER:UPDATE", 
                    "CUSTOMER:QUERY", 
                    "ASSET:QUERY", 
                    "OSQUERY:DOWNLOAD", 
                    "OSQUERY:READ", 
                    "FEATURE_SET:READ", 
                    "DASHBOARD:READ", 
                    "CURRENT_USER_PREFERENCE:READ", 
                    "CURRENT_USER_PREFERENCE:CREATE", 
                    "CURRENT_USER_PREFERENCE:UPDATE", 
                    "CURRENT_USER_PREFERENCE:DELETE", 
                    "CURRENT_USER_REPORT_SCHEDULE:CREATE", 
                    "CURRENT_USER_REPORT_SCHEDULE:READ", 
                    "CURRENT_USER_REPORT_SCHEDULE:UPDATE", 
                    "CURRENT_USER_REPORT_SCHEDULE:DELETE", 
                    "COMPLIANCE_FAILURE:READ", 
                    "COMPLIANCE_FAILURE:UPDATE", 
                    "CUSTOM_PROFILE:READ", 
                    "QUERY_JOB:CREATE", 
                    "QUERY_JOB:READ", 
                    "QUERY_JOB:UPDATE", 
                    "QUERY_JOB:DELETE", 
                    "EVENT_EXCLUDE_PROFILE:READ", 
                    "ATC_QUERY:READ", 
                    "REGISTRY_PATH:READ", 
                    "AUDIT_RULE:READ", 
                    "EXTERNAL_DASHBOARD:READ", 
                    "ALERT:CREATE", 
                    "ALERT:UPDATE", 
                    "ALERT:DELETE", 
                    "ALERT_RULE:CREATE", 
                    "ALERT_RULE:UPDATE", 
                    "ALERT_RULE:DELETE", 
                    "API_KEY:CREATE", 
                    "API_KEY:READ", 
                    "API_KEY:UPDATE", 
                    "API_KEY:DELETE", 
                    "ASSET:UPDATE", 
                    "ASSET:DELETE", 
                    "ASSET_GROUP_RULE:CREATE", 
                    "ASSET_GROUP_RULE:READ", 
                    "ASSET_GROUP_RULE:UPDATE", 
                    "ASSET_GROUP_RULE:DELETE", 
                    "CUSTOMER:UPDATE", 
                    "DESTINATION:CREATE", 
                    "DESTINATION:UPDATE", 
                    "DESTINATION:DELETE", 
                    "EVENT:CREATE", 
                    "EVENT:UPDATE", 
                    "EVENT:DELETE", 
                    "EVENT_RULE:CREATE", 
                    "EVENT_RULE:UPDATE", 
                    "EVENT_RULE:DELETE", 
                    "EXCEPTION:CREATE", 
                    "EXCEPTION:UPDATE", 
                    "EXCEPTION:DELETE", 
                    "FIM:CREATE", 
                    "FIM:UPDATE", 
                    "FIM:DELETE", 
                    "FLAG:CREATE", 
                    "FLAG:UPDATE", 
                    "FLAG:DELETE", 
                    "OBJECT_GROUP:CREATE", 
                    "OBJECT_GROUP:UPDATE", 
                    "OBJECT_GROUP:DELETE", 
                    "PROMETHEUS_TARGET:CREATE", 
                    "PROMETHEUS_TARGET:UPDATE", 
                    "PROMETHEUS_TARGET:DELETE", 
                    "QUERY:CREATE", 
                    "QUERY:UPDATE", 
                    "QUERY:DELETE", 
                    "QUERY_PACK:CREATE", 
                    "QUERY_PACK:UPDATE", 
                    "QUERY_PACK:DELETE", 
                    "REPORT:CREATE", 
                    "REPORT:UPDATE", 
                    "REPORT:DELETE", 
                    "REPORT_RUN:CREATE", 
                    "REPORT_RUN:UPDATE", 
                    "REPORT_RUN:DELETE", 
                    "SCHEDULED_GROUP:UPDATE", 
                    "SCHEDULED_GROUP:DELETE", 
                    "SCHEDULED_QUERY:CREATE", 
                    "SCHEDULED_QUERY:UPDATE", 
                    "SCHEDULED_QUERY:DELETE", 
                    "SNAPSHOT:CREATE", 
                    "SNAPSHOT:UPDATE", 
                    "SNAPSHOT:DELETE", 
                    "TAG:CREATE", 
                    "TAG:UPDATE", 
                    "TAG:DELETE", 
                    "TAG_RULE:CREATE", 
                    "TAG_RULE:UPDATE", 
                    "TAG_RULE:DELETE", 
                    "TEMPLATE:CREATE", 
                    "TEMPLATE:UPDATE", 
                    "TEMPLATE:DELETE", 
                    "THREAT:CREATE", 
                    "THREAT:UPDATE", 
                    "THREAT:DELETE", 
                    "USER:CREATE", 
                    "USER:UPDATE", 
                    "USER:DELETE", 
                    "USER_ROLE:CREATE", 
                    "USER_ROLE:UPDATE", 
                    "USER_ROLE:DELETE", 
                    "CURRENT_USER:READ", 
                    "CURRENT_USER:UPDATE", 
                    "CUSTOMER_FEATURE_SET:UPDATE", 
                    "USER_PREFERENCE:CREATE", 
                    "USER_PREFERENCE:READ", 
                    "USER_PREFERENCE:UPDATE", 
                    "USER_PREFERENCE:DELETE", 
                    "REPORT_SCHEDULE:CREATE", 
                    "REPORT_SCHEDULE:READ", 
                    "REPORT_SCHEDULE:UPDATE", 
                    "REPORT_SCHEDULE:DELETE", 
                    "AUDIT_LOGS:READ", 
                    "CUSTOM_PROFILE:CREATE", 
                    "CUSTOM_PROFILE:UPDATE", 
                    "CUSTOM_PROFILE:DELETE", 
                    "EVENT_EXCLUDE_PROFILE:CREATE", 
                    "EVENT_EXCLUDE_PROFILE:UPDATE", 
                    "EVENT_EXCLUDE_PROFILE:DELETE", 
                    "ATC_QUERY:CREATE", 
                    "ATC_QUERY:UPDATE", 
                    "ATC_QUERY:DELETE", 
                    "REGISTRY_PATH:CREATE", 
                    "REGISTRY_PATH:UPDATE", 
                    "REGISTRY_PATH:DELETE", 
                    "AUDIT_RULE:UPDATE", 
                    "AUDIT_RULE:DELETE", 
                    "AUDIT_RULE:CREATE", 
                    "EXTERNAL_DASHBOARD:CREATE", 
                    "EXTERNAL_DASHBOARD:UPDATE", 
                    "EXTERNAL_DASHBOARD:DELETE"
                ], 
                "customerId": "e8213ef3-ef92-460e-a542-46dccd700c16", 
                "createdAt": "2018-09-24T17:24:41.194Z", 
                "name": "admin"
            }
        }, 
        "email": "goo@test.com", 
        "name": "B schmoll", 
        "id": "33436e24-f30f-42d0-8438-d948be12b5af"
    }
}
```

##### Human Readable Output
### Uptycs User Information
|name|email|id|
|---|---|---|
|B schmoll|goo@test.com|33436e24-f30f-42d0-8438-d948be12b5af|


### 15. uptycs-get-threat-indicators
---
get Uptycs threat indicators
##### Base Command

`uptycs-get-threat-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | the specific indicator you wish to search for.  This can be an IP address, a Bad Domain, etc. as well ass any indicators you have added. | Optional | 
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-get-threat-indicators limit=1`

##### Context Example
```
{
    "Uptycs.ThreatIndicators": [
        {
            "indicator": "54.165.17.209", 
            "description": "malware.com", 
            "threatId": "b3f44b34-f6a1-46bc-88f1-9755e3ac1a65", 
            "indicatorType": "IPv4", 
            "createdAt": "2019-07-19T16:44:17.511Z", 
            "id": "8e54f94c-469a-4737-9eef-4e650a93ab58", 
            "isActive": true
        }
    ]
}
```

##### Human Readable Output
### Uptycs Threat Indicators
|id|indicator|description|indicatorType|createdAt|isActive|threatId|
|---|---|---|---|---|---|---|
|8e54f94c-469a-4737-9eef-4e650a93ab58|54.165.17.209|malware.com|IPv4|2019-07-19T16:44:17.511Z|true|b3f44b34-f6a1-46bc-88f1-9755e3ac1a65|


### 16. uptycs-get-threat-sources
---
get Uptycs threat sources
##### Base Command

`uptycs-get-threat-sources`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-get-threat-sources limit=1`

##### Context Example
```
{
    "Uptycs.ThreatSources": [
        {
            "name": "AlienVault Open Threat Exchange Malicious Domains and IPs", 
            "url": "4533da856e43f06ee00bb5f1adf170a0ce5cacaca5992ab1279733c2bdd0a88c", 
            "enabled": true, 
            "custom": false, 
            "lastDownload": "2019-05-13T01:00:05.934Z", 
            "createdAt": "2019-05-12T01:01:04.154Z", 
            "description": "A feed of malicious domains and IP addresses"
        }
    ]
}
```

##### Human Readable Output
### Uptycs Threat Sources
|name|description|url|enabled|custom|createdAt|lastDownload|
|---|---|---|---|---|---|---|
|AlienVault Open Threat Exchange Malicious Domains and IPs|A feed of malicious domains and IP addresses|4533da856e43f06ee00bb5f1adf170a0ce5cacaca5992ab1279733c2bdd0a88c|true|false|2019-05-12T01:01:04.154Z|2019-05-13T01:00:05.934Z|


### 17. uptycs-get-threat-vendors
---
get Uptycs threat vendors
##### Base Command

`uptycs-get-threat-vendors`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-get-threat-vendors `

##### Context Example
```
{
    "Uptycs.ThreatVendors": [
        {
            "name": "Bschmoll Inc.-Threats", 
            "url": null, 
            "updatedAt": "2018-11-20T19:15:05.611Z", 
            "customerId": "e8213ef3-ef92-460e-a542-46dccd700c16", 
            "numThreats": null, 
            "numIocs": null, 
            "lastDownload": null, 
            "id": "42b9220c-7e29-4fd8-9cf7-9f811e851f8e", 
            "createdAt": "2018-11-20T19:15:05.611Z", 
            "description": null
        }
    ]
}
```

##### Human Readable Output
### Uptycs Threat Vendors
|description|url|updatedAt|customerId|numIocs|numThreats|lastDownload|id|createdAt|name|
|---|---|---|---|---|---|---|---|---|---|
|||2018-11-20T19:15:05.611Z|e8213ef3-ef92-460e-a542-46dccd700c16||||42b9220c-7e29-4fd8-9cf7-9f811e851f8e|2018-11-20T19:15:05.611Z|Bschmoll Inc.-Threats|


### 18. uptycs-get-parent-information
---
get the parent process information for a particular child process
##### Base Command

`uptycs-get-parent-information`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id" and "host_name_is" at the same time. | Optional | 
| child_add_time | Time that the specified process was spawned. | Required | 
| host_name_is | Hostname for asset which spawned the specified process. | Optional | 
| parent | pid for the parent process. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Parent.pid | number | pid of the process (this is the same number as the input argument 'parent') | 
| Uptycs.Parent.upt_hostname | string | hostname for asset which spawned the specified process | 
| Uptycs.Parent.upt_asset_id | string | asset id for asset which spawned the specified process | 
| Uptycs.Parent.parent | number | pid for the parent process (this is the parent of the input argument 'parent') | 
| Uptycs.Parent.upt_add_time | date | time that the process was spawned | 
| Uptycs.Parent.upt_remove_time | date | time that the process was removed | 
| Uptycs.Parent.name | string | name of the process | 
| Uptycs.Parent.path | string | path to the process binary | 
| Uptycs.Parent.cmdline | string | complete argv for the process | 
| Uptycs.Parent.pgroup | number | process group | 
| Uptycs.Parent.cwd | string | process current working directory | 


##### Command Example
`uptycs-get-parent-information asset_id="984d4a7a-9f3a-580a-a3ef-2841a561669b" child_add_time="2019-01-29 16:14:27.000" parent=484`

##### Context Example
```
{
    "Uptycs.Parent": [
        {
            "name": "VBoxSVC", 
            "parent": 1, 
            "upt_add_time": "2019-01-28 14:16:58.000", 
            "pid": 484, 
            "upt_remove_time": "2019-01-29 19:21:31.000 UTC", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "/Applications/VirtualBox.app/Contents/MacOS/VBoxSVC --auto-shutdown", 
            "upt_hostname": "kyle-mbp-work", 
            "pgroup": 484, 
            "path": "/Applications/VirtualBox.app/Contents/MacOS/VBoxSVC", 
            "cwd": "/Applications", 
            "upt_day": 20190128
        }
    ]
}
```

##### Human Readable Output
### Parent process information
|upt_hostname|parent|pid|name|path|cmdline|
|---|---|---|---|---|---|
|kyle-mbp-work|1|484|VBoxSVC|/Applications/VirtualBox.app/Contents/MacOS/VBoxSVC|/Applications/VirtualBox.app/Contents/MacOS/VBoxSVC --auto-shutdown|


### 19. uptycs-post-threat-source
---
post a new threat source to your threat sources in Uptycs
##### Base Command

`uptycs-post-threat-source`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | A short description for the threat source | Required | 
| entry_id | entry_id for the file with threat information.  This file should be uploaded to demisto in the Playground War Room using the paperclip icon next to the CLI. | Required | 
| filename | The name of the file being uploaded | Required | 
| name | The name for the threat source | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-post-threat-source  name="testThreatSources" description="testing Uptycs API" entry_id="4322@27d41dbb-9676-4408-88bf-51193334caf7" filename="threatSourcesTest.csv"`

##### Context Example
```

```

##### Human Readable Output
Uptycs Posted Threat Source

### 20. uptycs-get-users
---
get a list of Uptycs users
##### Base Command

`uptycs-get-users`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.Users.id | string | unique Uptycs id for the user | 
| Uptycs.Users.name | string | Uptycs user's name | 
| Uptycs.Users.email | string | Uptycs user's email address | 
| Uptycs.Users.createdAt | date | datetime this user was added | 
| Uptycs.Users.updatedAt | date | last time this user was updated | 
| Uptycs.Users.admin | boolean | true if this user has admin privileges, false otherwise | 
| Uptycs.Users.active | boolean | true if this user is currently active, false otherwise | 


##### Command Example
`uptycs-get-users limit=1`

##### Context Example
```
{
    "Uptycs.Users": [
        {
            "name": "B schmoll", 
            "admin": true, 
            "id": "33436e24-f30f-42d0-8438-d948be12b5af", 
            "updatedAt": "2018-09-25T16:10:28.140Z", 
            "active": true, 
            "email": "goo@test.com", 
            "createdAt": "2018-09-24T17:24:38.635Z"
        }
    ]
}
```

##### Human Readable Output
### Uptycs Users
|name|email|id|admin|active|createdAt|updatedAt|
|---|---|---|---|---|---|---|
|B schmoll|goo@test.com|33436e24-f30f-42d0-8438-d948be12b5af|true|true|2018-09-24T17:24:38.635Z|2018-09-25T16:10:28.140Z|


### 21. uptycs-get-asset-groups
---
get Uptycs asset groups
##### Base Command

`uptycs-get-asset-groups`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.AssetGroups.id | string | unique Uptycs id for a particular object group | 
| Uptycs.AssetGroups.custom | boolean | true if this is a custom asset group, false otherwise | 
| Uptycs.AssetGroups.createdAt | date | datetime the group was created | 
| Uptycs.AssetGroups.updatedAt | date | datetime the group was last updated | 


##### Command Example
`uptycs-get-asset-groups `

##### Context Example
```
{
    "Uptycs.AssetGroups": [
        {
            "name": "assets", 
            "description": "Default asset group", 
            "custom": false, 
            "updatedAt": "2018-09-24T17:24:45.604Z", 
            "id": "106eef5e-c3a6-44eb-bb3d-1a2087cded3d", 
            "createdAt": "2018-09-24T17:24:45.604Z", 
            "objectType": "ASSET"
        }, 
        {
            "name": "enrolling", 
            "description": "Enrolling asset group", 
            "custom": false, 
            "updatedAt": "2018-09-24T17:24:45.601Z", 
            "id": "a73353c1-1b27-4eea-9a7c-d2f946cca030", 
            "createdAt": "2018-09-24T17:24:45.601Z", 
            "objectType": "ASSET"
        }
    ]
}
```

##### Human Readable Output
### Uptycs Users
|id|name|description|objectType|custom|createdAt|updatedAt|
|---|---|---|---|---|---|---|
|106eef5e-c3a6-44eb-bb3d-1a2087cded3d|assets|Default asset group|ASSET|false|2018-09-24T17:24:45.604Z|2018-09-24T17:24:45.604Z|
|a73353c1-1b27-4eea-9a7c-d2f946cca030|enrolling|Enrolling asset group|ASSET|false|2018-09-24T17:24:45.601Z|2018-09-24T17:24:45.601Z|


### 22. uptycs-get-user-asset-groups
---
get a list of users in a particular asset group
##### Base Command

`uptycs-get-user-asset-groups`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_group_id | return a list of users with access to this asset group | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-get-user-asset-groups asset_group_id="106eef5e-c3a6-44eb-bb3d-1a2087cded3d"`

##### Context Example
```
{
    "Uptycs.UserGroups": {
        "B schmoll": {
            "email": "goo@test.com", 
            "id": "33436e24-f30f-42d0-8438-d948be12b5af"
        }, 
        "Mike Boldi": {
            "email": "woo@test.com", 
            "id": "e43b0119-8d23-4ea2-9fd9-3a9ff14fc195"
        }, 
        "Milan Shah": {
            "email": "foo@test.com", 
            "id": "89d26aa4-f0a8-48d9-a174-ce5285d9dd60"
        }
    }
}
```

##### Human Readable Output
### Uptycs User Asset Groups
|B schmoll|Mike Boldi|Milan Shah|
|---|---|---|
|email: goo@test.com<br/>id: 33436e24-f30f-42d0-8438-d948be12b5af|email: woo@test.com<br/>id: e43b0119-8d23-4ea2-9fd9-3a9ff14fc195|email: foo@test.com<br/>id: 89d26aa4-f0a8-48d9-a174-ce5285d9dd60|


### 23. uptycs-get-threat-indicator
---
retrieve information about a specific threat indicator using a unique threat indicator id
##### Base Command

`uptycs-get-threat-indicator`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_id | unique Uptycs id which identifies a specific threat indicator | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.ThreatIndicator.threat_source_id | string | unique Uptycs id which identifies the source of this specific threat indicator | 
| Uptycs.ThreatIndicator.threat_vendor_id | string | unique Uptycs id which identifies the vendor of this specific threat source | 
| Uptycs.ThreatIndicator.indicatorType | string | type of threat indicator (IPv4, domain,...) | 
| Uptycs.ThreatIndicator.indicator | string | threat indicator | 
| Uptycs.ThreatIndicator.createdAt | date | datetime the threat indicator was created | 
| Uptycs.ThreatIndicator.threadId | string | unique id for the group of threat indicators this thread indicator belongs to | 
| Uptycs.ThreatIndicator.id | string | unique id for this particular threat indicator | 


##### Command Example
`uptycs-get-threat-indicator indicator_id="0ab619bb-cfe0-4db0-8a31-0a71fcc2a362"`

##### Context Example
```
{
    "Uptycs.ThreatIndicator": {
        "indicator": "92.242.140.21", 
        "description": "nishant.uptycs.io", 
        "threatId": "60e2e9eb-f756-4a4d-a85d-55aa8167d59d", 
        "threat_source_name": "test-bad-ips", 
        "threat_vendor_id": "42b9220c-7e29-4fd8-9cf7-9f811e851f8e", 
        "indicatorType": "IPv4", 
        "createdAt": "2019-01-10T21:25:49.280Z", 
        "updatedAt": "2019-01-10T21:25:49.280Z", 
        "threat_source_id": "c67d0821-f2f2-44ee-b3a8-a0bae5b04e55", 
        "id": "0ab619bb-cfe0-4db0-8a31-0a71fcc2a362", 
        "isActive": true
    }
}
```

##### Human Readable Output
### Uptycs Threat Indicator
|id|indicator|description|indicatorType|createdAt|isActive|threatId|
|---|---|---|---|---|---|---|
|0ab619bb-cfe0-4db0-8a31-0a71fcc2a362|92.242.140.21|nishant.uptycs.io|IPv4|2019-01-10T21:25:49.280Z|true|60e2e9eb-f756-4a4d-a85d-55aa8167d59d|


### 24. uptycs-get-threat-source
---
retrieve information about a specific threat source
##### Base Command

`uptycs-get-threat-source`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_source_id | unique Uptycs id for the threat source you wish to retrive | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-get-threat-source threat_source_id="20ee2177-4fdc-4070-a046-945048373dd1"`

##### Context Example
```
{
    "Uptycs.ThreatSources": {
        "name": "Debian Linux vulnerabilities", 
        "url": "https://vulners.com/api/v3/archive/collection/?type=debian", 
        "enabled": true, 
        "custom": false, 
        "lastDownload": null, 
        "createdAt": "2018-09-14T18:43:54.832Z", 
        "description": "Debian Linux vulnerabilities"
    }
}
```

##### Human Readable Output
### Uptycs Threat Sources
|name|description|url|enabled|custom|createdAt|lastDownload|
|---|---|---|---|---|---|---|
|Debian Linux vulnerabilities|Debian Linux vulnerabilities|`https://vulners.com/api/v3/archive/collection/?type=debian`|true|false|2018-09-14T18:43:54.832Z||


### 25. uptycs-get-process-events
---
find process events which are running or have run on a registered Uptycs asset
##### Base Command

`uptycs-get-process-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id", "host_name_is" or "host_name_like" at the same time. | Optional | 
| host_name_is | Only return assets with this hostname.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| host_name_like | Only return assets with this string in the hostname.  Use this to find a selection of assets with similar hostnames.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 
| start_window | Beginning of window to search for open connections.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| end_window | End of window to search for open connections.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| time | Exact time at which the process was spawned. | Optional | 
| time_ago | Specifies how far back you want to look.  Format examples: 2 hours, 4 minutes, 6 month, 1 day, etc. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.ProcessEvents.pid | number | pid for a particular process | 
| Uptycs.ProcessEvents.parent | number | pid for the parent of a particular process | 
| Uptycs.ProcessEvents.upt_asset_id | string | uptycs asset id for the asset which is running (or ran) the process | 
| Uptycs.ProcessEvents.upt_hostname | string | host name for the asset which is running (or ran) the process | 
| Uptycs.ProcessEvents.upt_time | date | time at which the process was spawned | 
| Uptycs.ProcessEvents.path | string | path to the process binary | 
| Uptycs.ProcessEvents.cmdline | string | comeplete argv for the process | 
| Uptycs.ProcessEvents.cwd | string | process current working directory | 


##### Command Example
`uptycs-get-process-events limit=1`

##### Context Example
```
{
    "Uptycs.ProcessEvents": [
        {
            "parent": 60065, 
            "pid": 60067, 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "/usr/sbin/spctl --status ", 
            "upt_hostname": "kyle-mbp-work", 
            "upt_time": "2019-07-19 09:29:47.000", 
            "path": "/usr/sbin/spctl", 
            "cwd": null
        }
    ]
}
```

##### Human Readable Output
### Process events
|upt_hostname|pid|path|upt_time|parent|cmdline|
|---|---|---|---|---|---|
|kyle-mbp-work|60067|/usr/sbin/spctl|2019-07-19 09:29:47.000|60065|/usr/sbin/spctl --status |


### 26. uptycs-get-process-event-information
---
get information for a particular process event
##### Base Command

`uptycs-get-process-event-information`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id" and "host_name_is" at the same time. | Optional | 
| host_name_is | Hostname for asset which spawned the specified process. | Optional | 
| pid | pid for the process. | Required | 
| time | Time that the specified process was spawned. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.ProcEvent.pid | number | pid for the process | 
| Uptycs.ProcEvent.upt_hostname | string | hostname for asset which spawned the specified process | 
| Uptycs.ProcEvent.upt_asset_id | string | asset id for asset which spawned the specified process | 
| Uptycs.ProcEvent.parent | number | pid for the parent process | 
| Uptycs.ProcEvent.upt_time | date | time that the process was spawned | 
| Uptycs.ProcEvent.path | string | path to the process binary | 
| Uptycs.ProcEvent.cmdline | string | comeplete argv for the process | 
| Uptycs.ProcEvent.cwd | string | process current working directory | 


##### Command Example
`uptycs-get-process-event-information asset_id="984d4a7a-9f3a-580a-a3ef-2841a561669b" pid=3318 time="2019-02-28 18:43:04.000"`

##### Context Example
```
{
    "Uptycs.ProcEvent": [
        {
            "parent": 1, 
            "pid": 3318, 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "xpcproxy com.apple.WebKit.WebContent.024FB342-0ECE-4E09-82E1-B9C9CF5F9CDF 3266 ", 
            "upt_hostname": "kyle-mbp-work", 
            "upt_time": "2019-02-28 18:43:04.000", 
            "path": "/dev/console", 
            "cwd": null
        }
    ]
}
```

##### Human Readable Output
### Process event information
|upt_hostname|parent|pid|path|cmdline|
|---|---|---|---|---|
|kyle-mbp-work|1|3318|/dev/console|xpcproxy com.apple.WebKit.WebContent.024FB342-0ECE-4E09-82E1-B9C9CF5F9CDF 3266 |


### 27. uptycs-get-socket-events
---
find processes which opened a socket
##### Base Command

`uptycs-get-socket-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id", "host_name_is" or "host_name_like" at the same time. | Optional | 
| host_name_is | Only return assets with this hostname.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| host_name_like | Only return assets with this string in the hostname.  Use this to find a selection of assets with similar hostnames.  Do not use arguments "host_name_is" and "host_name_like" at the same time. | Optional | 
| ip | IP address which process opened a socket to. | Optional | 
| limit | Limit the number of entries returned.  Use -1 to return all entries (may run slow or cause a time out). | Optional | 
| start_window | Beginning of window to search for open sockets.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| end_window |  End of window to search for open sockets.  Format is "YYYY-MM-DD HH:MM:SS.000", for example, March 15, 2019 at 1:52:36 am would be written as "2019-03-15 01:52:36.000". | Optional | 
| time | Exact time at which the socket was opened. | Optional | 
| time_ago | Specifies how far back you want to look.  Format examples: 2 hours, 4 minutes, 6 month, 1 day, etc. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.SocketEvents.pid | number | pid of process which opened a connection to a specified IP | 
| Uptycs.SocketEvents.upt_hostname | string | hostname of the asset which ran the specified process | 
| Uptycs.SocketEvents.upt_time | date | time at which the connection was opened | 
| Uptycs.SocketEvents.path | string | file path to the process being run | 
| Uptycs.SocketEvents.local_address | string | local IP for specified connection | 
| Uptycs.SocketEvents.remote_address | string | remote IP for specified connection | 
| Uptycs.SocketEvents.local_port | number | local port for specified connection | 
| Uptycs.SocketEvents.remote_port | number | remote port for specified connection | 
| Uptycs.SocketEvents.upt_asset_id | string | asset id for asset which ran the specified process | 
| Uptycs.SocketEvents.socket | number | socket used to open the connection | 
| Uptycs.SocketEvents.family | number | network protocol | 
| Uptycs.SocketEvents.action | string | type of socket event (accept, connect, or bind) | 
| Uptycs.SocketEvents.protocol | number | transfer protocol | 


##### Command Example
`uptycs-get-socket-events limit=1 remote_address="98.239.146.208"`

##### Context Example
```
{
    "Uptycs.SocketEvents": [
        {
            "protocol": null, 
            "socket": null, 
            "family": 2, 
            "local_port": 47873, 
            "remote_port": null, 
            "pid": 89, 
            "remote_address": "17.142.171.8", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "upt_time": "2019-07-19 09:29:52.000", 
            "upt_hostname": "kyle-mbp-work", 
            "path": null, 
            "action": "connect", 
            "local_address": "0.0.0.0"
        }
    ]
}
```

##### Human Readable Output
### Socket events
|upt_hostname|pid|local_address|remote_address|upt_time|local_port|action|
|---|---|---|---|---|---|---|
|kyle-mbp-work|89|0.0.0.0|17.142.171.8|2019-07-19 09:29:52.000|47873|connect|


### 28. uptycs-get-parent-event-information
---
find information for parent process events which are running or have run on a registered Uptycs assert
##### Base Command

`uptycs-get-parent-event-information`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id" and "host_name_is" at the same time. | Optional | 
| child_add_time | Time that the specified process was spawned. | Required | 
| host_name_is | Hostname for asset which spawned the specified process. | Optional | 
| parent | pid for the parent process. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.ParentEvent.pid | number | pid of the process (this is the same number as the input argument 'parent') | 
| Uptycs.ParentEvent.upt_hostname | string | hostname for asset which spawned the specified process | 
| Uptycs.ParentEvent.upt_asset_id | string | asset id for asset which spawned the specified process | 
| Uptycs.ParentEvent.parent | number | pid for the parent process (this is the parent of the input argument 'parent') | 
| Uptycs.ParentEvent.upt_time | date | time that the process was spawned | 
| Uptycs.ParentEvent.path | string | path to the parent process binary | 
| Uptycs.ParentEvent.cmdline | string | complete argv for the parent process | 
| Uptycs.ParentEvent.cwd | string | parent process current working cirectory | 


##### Command Example
`uptycs-get-parent-event-information child_add_time="2019-05-07 12:24:34.000" parent=9347 host_name_is="kyle-mbp-work"`

##### Context Example
```
{
    "Uptycs.ParentEvent": [
        {
            "parent": 75, 
            "pid": 9347, 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "cmdline": "/sbin/mount -t hfs -o -u=99,-g=99,-m=755,nodev,noowners,nosuid,owners,nobrowse,-t=4m /dev/disk2s2 /Volumes/Time Machine Backups ", 
            "upt_hostname": "kyle-mbp-work", 
            "upt_time": "2019-05-07 12:24:34.000", 
            "path": "/sbin/mount", 
            "cwd": null
        }
    ]
}
```

##### Human Readable Output
### Parent process event information
|upt_hostname|parent|pid|path|cmdline|
|---|---|---|---|---|
|kyle-mbp-work|75|9347|/sbin/mount|/sbin/mount -t hfs -o -u=99,-g=99,-m=755,nodev,noowners,nosuid,owners,nobrowse,-t=4m /dev/disk2s2 /Volumes/Time Machine Backups |


### 29. uptycs-get-socket-event-information
---
get information for a particular socket event
##### Base Command

`uptycs-get-socket-event-information`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Only return assets with this asset id.  Do not use arguments "asset_id" and "host_name_is" at the same time. | Optional | 
| host_name_is | Hostname for asset which spawned the specified process. | Optional | 
| ip | IP address which process opened a socket to. | Required | 
| time | Time that the specified connection was opened. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Uptycs.SocketEvents.pid | number | pid of process which opened a connection to a specified IP | 
| Uptycs.SocketEvents.upt_hostname | string | hostname of the asset which ran the specified process | 
| Uptycs.SocketEvents.upt_time | date | time at which the connection was opened | 
| Uptycs.SocketEvents.path | string | file path to the process being run | 
| Uptycs.SocketEvents.local_address | string | local IP for specified connection | 
| Uptycs.SocketEvents.remote_address | string | remote IP for specified connection | 
| Uptycs.SocketEvents.local_port | number | local port for specified connection | 
| Uptycs.SocketEvents.remote_port | number | remote port for specified connection | 
| Uptycs.SocketEvents.upt_asset_id | string | asset id for asset which ran the specified process | 
| Uptycs.SocketEvents.action | string | type of socket event (accept, connect, or bind) | 
| Uptycs.SocketEvents.family | number | network protocol | 
| Uptycs.SocketEvents.socket | number | socket used to open the connection | 
| Uptycs.SocketEvents.protocol | number | transfer protocol | 


##### Command Example
`uptycs-get-socket-event-information ip="18.213.163.112" time="2019-03-18 14:34:31.000"`

##### Context Example
```
{
    "Uptycs.SocketEvent": [
        {
            "protocol": null, 
            "socket": "", 
            "family": 2, 
            "local_port": 47873, 
            "remote_port": null, 
            "pid": 16570, 
            "remote_address": "18.213.163.112", 
            "upt_asset_id": "984d4a7a-9f3a-580a-a3ef-2841a561669b", 
            "upt_time": "2019-03-18 14:34:31.000", 
            "upt_hostname": "kyle-mbp-work", 
            "path": null, 
            "action": "connect", 
            "local_address": "0.0.0.0"
        }
    ]
}
```

##### Human Readable Output
### Socket event information
|upt_hostname|pid|local_address|remote_address|upt_time|local_port|action|
|---|---|---|---|---|---|---|
|kyle-mbp-work|16570|0.0.0.0|18.213.163.112|2019-03-18 14:34:31.000|47873|connect|


### 30. uptycs-get-asset-tags
---
Retrieve a list of tags for a particular asset
##### Base Command

`uptycs-get-asset-tags`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Uptycs asset id for the asset you are looking for. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-get-asset-tags asset_id="984d4a7a-9f3a-580a-a3ef-2841a561669b"`

##### Context Example
```
{
    "Uptycs.AssetTags": [
        "Uptycs=work laptop", 
        "owner=Uptycs office", 
        "network=low", 
        "cpu=unknown", 
        "memory=unknown", 
        "disk=high"
    ]
}
```

##### Human Readable Output
### Uptycs Asset Tags for asset id: 984d4a7a-9f3a-580a-a3ef-2841a561669b
|Tags|
|---|
|Uptycs=work laptop|
|owner=Uptycs office|
|network=low|
|cpu=unknown|
|memory=unknown|
|disk=high|


### 31. uptycs-get-saved-queries
---
Retrieve a saved query or list of all saved queries
##### Base Command

`uptycs-get-saved-queries`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | limit the number of entries returned | Optional | 
| query_id | Only return the query with this unique id | Optional | 
| name | Only return the query with this name | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-get-saved-queries name="test_saved_query"`

##### Context Example
```
{
    "Uptycs.SavedQueries": [
        {
            "seedId": "fec83a16-7c2a-4c9e-8621-7f030a14dfa4", 
            "updatedAt": "2019-05-10T19:07:46.480Z", 
            "query": "select * from upt_assets limit 1", 
            "viewConfig": null, 
            "id": "16de057d-6f69-46b0-80d0-46cb9348c8fe", 
            "createdAt": "2019-05-10T19:07:46.480Z", 
            "deleted_at": null, 
            "resultView": "TABLE", 
            "custom": true, 
            "shared": true, 
            "customerId": "e8213ef3-ef92-460e-a542-46dccd700c16", 
            "type": "default", 
            "assetView": "LIST", 
            "description": "this is a test query", 
            "deletedAt": null, 
            "createdBy": "33436e24-f30f-42d0-8438-d948be12b5af", 
            "updatedBy": "33436e24-f30f-42d0-8438-d948be12b5af", 
            "name": "test_saved_query", 
            "executionType": "global", 
            "parameters": null, 
            "deletedBy": null, 
            "grouping": "\"\""
        }
    ]
}
```

##### Human Readable Output
### Uptycs Saved Queries
|name|description|query|executionType|grouping|id|
|---|---|---|---|---|---|
|test_saved_query|this is a test query|select * from upt_assets limit 1|global|""|16de057d-6f69-46b0-80d0-46cb9348c8fe|


### 32. uptycs-run-saved-query
---
Run a saved query
##### Base Command

`uptycs-run-saved-query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the query you want to run | Optional | 
| query_id | The unique id for the query you want to run | Optional | 
| asset_id | *realtime queries only*  This argument should be used when one wants to run a realtime query on a particular asset. | Optional | 
| host_name_is | *realtime queries only*  Only return assets with this hostname | Optional | 
| host_name_like | *realtime queries only* . Only return assets with this string in the hostname. | Optional | 
| variable_arguments | If your saved query has variable arguments, write them here in a json format where the key is the name of the variable argument and value is the value you want to use for this particular query. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-run-saved-query name="test_saved_query"`

##### Context Example
```
{
    "Uptycs.RunQuery": [
        {
            "city_id": "6ee1f7ef-ad7d-46b1-9f74-384299c90830", 
            "updated_at": "2018-09-25 16:14:28.898", 
            "hardware_vendor": "Dell Inc.", 
            "disabled": false, 
            "os_key": "windows_10.0", 
            "deleted_at": null, 
            "id": "4c4c4544-0044-3910-8033-c8c04f5a4832", 
            "os_version": "10.0.14393", 
            "osquery_version": "3.2.6.15-Uptycs", 
            "gateway": "50.79.168.117", 
            "hardware_model": "PowerEdge T30", 
            "cpu_brand": "Intel(R) Xeon(R) CPU E3-1225 v5 @ 3.30GHz", 
            "live": false, 
            "location": "United States", 
            "latitude": 37.751, 
            "host_name": "caol", 
            "status": "active", 
            "last_enrolled_at": "2018-09-25 16:14:28.863", 
            "description": null, 
            "object_group_id": "106eef5e-c3a6-44eb-bb3d-1a2087cded3d", 
            "last_activity_at": "2018-09-26 17:03:16.187", 
            "os": "Microsoft Windows Server 2016 Datacenter", 
            "created_at": "2018-09-25 16:14:28.881", 
            "longitude": -97.822, 
            "memory_mb": 16250, 
            "logical_cores": 4, 
            "os_flavor": "windows", 
            "cores": 4, 
            "hardware_serial": "HD93ZH2"
        }
    ]
}
```

##### Human Readable Output
### Uptycs Query Results
|city_id|updated_at|hardware_vendor|disabled|last_enrolled_at|deleted_at|gateway|cpu_brand|osquery_version|id|hardware_model|os_version|live|location|latitude|host_name|status|os_key|description|object_group_id|last_activity_at|hardware_serial|created_at|longitude|memory_mb|logical_cores|os_flavor|cores|os|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|6ee1f7ef-ad7d-46b1-9f74-384299c90830|2018-09-25 16:14:28.898|Dell Inc.|false|2018-09-25 16:14:28.863||50.79.168.117|Intel(R) Xeon(R) CPU E3-1225 v5 @ 3.30GHz|3.2.6.15-Uptycs|4c4c4544-0044-3910-8033-c8c04f5a4832|PowerEdge T30|10.0.14393|false|United States|37.751|caol|active|windows_10.0||106eef5e-c3a6-44eb-bb3d-1a2087cded3d|2018-09-26 17:03:16.187|HD93ZH2|2018-09-25 16:14:28.881|-97.822|16250|4|windows|4|Microsoft Windows Server 2016 Datacenter|


### 33. uptycs-post-saved-query
---
Save a query to the Uptycs DB
##### Base Command

`uptycs-post-saved-query`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | A short description for the query | Optional | 
| execution_type | The type of query (global or realtime). | Required | 
| name | The name for the query.  This should be unique to this query. | Required | 
| query | The query which will be saved | Required | 
| type | Type of issue the query addresses. | Optional | 
| grouping | Add the query to a group of queries. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
`uptycs-post-saved-query name="process_query" query="select * from processes where name=:name limit 1" execution_type=global description="This is a test query with a variable argument for the column 'name’"`

##### Context Example
```
{
    "Uptycs.PostedQuery": {
        "links": [
            {
                "href": "/api/customers/e8213ef3-ef92-460e-a542-46dccd700c16/queries/cc40b97a-46ab-4392-9f58-c4659e8ef4c1", 
                "rel": "self"
            }, 
            {
                "href": "/api/customers/e8213ef3-ef92-460e-a542-46dccd700c16/queries", 
                "rel": "parent"
            }
        ], 
        "updatedAt": "2019-07-19T17:52:18.476Z", 
        "query": "select * from processes where name=:name limit 1", 
        "viewConfig": null, 
        "id": "cc40b97a-46ab-4392-9f58-c4659e8ef4c1", 
        "createdAt": "2019-07-19T17:52:18.476Z", 
        "seedId": "9a6dfb16-695a-43c2-ac15-201cbd8040f8", 
        "resultView": "TABLE", 
        "custom": true, 
        "shared": true, 
        "customerId": "e8213ef3-ef92-460e-a542-46dccd700c16", 
        "type": "default", 
        "assetView": "LIST", 
        "description": "This is a test query with a variable argument for the column 'name\u2019", 
        "deletedAt": null, 
        "createdBy": "33436e24-f30f-42d0-8438-d948be12b5af", 
        "updatedBy": "33436e24-f30f-42d0-8438-d948be12b5af", 
        "name": "process_query", 
        "executionType": "global", 
        "parameters": null, 
        "deletedBy": null, 
        "grouping": "\"\""
    }
}
```

##### Human Readable Output
### Uptycs Posted Query
|name|type|description|query|executionType|grouping|custom|
|---|---|---|---|---|---|---|
|process_query|default|This is a test query with a variable argument for the column 'name’|select * from processes where name=:name limit 1|global|""|true|


## Additional Information
---

In order to create an instance of the integration, a user API key and secret must be downloaded from the users Uptycs account.  After signing in, navigate to Configuration->Users.  At the bottom left of the screen you will see a window labeled "User API key".  Click download.  The downloaded file will have all the information necessary to create the instance.

## Known Limitations
---

While the Demisto-Uptycs integration provides multiple commands with which to access the Uptycs backend, not all features are supported.  In particular, configuration changes are best made using the Uptycs UI.  Many of the commands have a limit set to reduce the number of rows returned from a query or api call.  The limit can be raised, or turned off, however, this may cause the queries take longer to return and potentially return large numbers of rows.  When writing queries, it can sometimes be easier to test using the Uptycs UI rather than the integration.

