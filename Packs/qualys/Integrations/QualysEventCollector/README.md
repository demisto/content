Qualys Event Collector fetches Activity Logs and host vulnerabilities.
This integration was integrated and tested with version 3.15.2.0-1 of Qualys.

## Configure Qualys Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**. 
2. Search for Qualys Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | Username |  | True |
    | Password |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | First fetch time |  | True |
    | Host Detections Fetch Interval | Time between fetches of host detections \(for example 12 hours, 60 minutes, etc\). | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### qualys-get-activity-logs

***
Gets activity logs from Qualys.

#### Base Command

`qualys-get-activity-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return. | Optional | 
| since_datetime | Date to return results from. | Optional | 
| offset | Offset which events to return. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!qualys-get-activity-logs limit=2```
#### Human Readable Output

>### Activity Logs
>|Action|Date|Details|Module| User IP | User Name |User Role|_time|event_type|
>|---|---|---|---|---------|-----------|---|---|---|
>| request | 2023-06-11T08:30:49Z | API: /api/2.0/fo/activity_log/index.php | auth | 1.1.1.1 | demisto   | Manager | 2023-06-11T08:30:49Z | activity_log |
>| request | 2023-06-11T08:30:47Z | API: /api/2.0/fo/asset/host/vm/detection/index.php | auth | 2.2.2.2 | demisto  | Manager | 2023-06-11T08:30:47Z | activity_log |


### qualys-get-host-detections

***
Gets host detections from Qualys.

#### Base Command

`qualys-get-host-detections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum results to return. | Optional | 
| offset | Offset which events to return. | Optional | 
| vm_scan_date_after | Date to return results from. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!qualys-get-host-detections limit=2```
#### Human Readable Output

>### Host List Detection
>| DETECTION                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | DNS        |DNS_DATA|ID| IP      |LAST_PC_SCANNED_DATE|LAST_SCAN_DATETIME|LAST_VM_SCANNED_DATE|LAST_VM_SCANNED_DURATION|OS|TRACKING_METHOD|_time|event_type|
>|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|---|---|---------|---|---|---|---|---|---|---|---|
>| QID: 38794<br/>TYPE: Confirmed<br/>SEVERITY: 3<br/>PORT: 443<br/>PROTOCOL: tcp<br/>SSL: 1<br/>RESULTS: TLSv1.1 is supported<br/>STATUS: Active<br/>FIRST_FOUND_DATETIME: 2021-03-16T09:34:16Z<br/>LAST_FOUND_DATETIME: 2023-05-16T15:26:01Z<br/>TIMES_FOUND: 213<br/>LAST_TEST_DATETIME: 2023-05-16T15:26:01Z<br/>LAST_UPDATE_DATETIME: 2023-05-16T15:26:53Z<br/>IS_IGNORED: 0<br/>IS_DISABLED: 0<br/>LAST_PROCESSED_DATETIME: 2023-05-16T15:26:53Z                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | one.one.one.one | HOSTNAME: one<br/>DOMAIN: one.one.one<br/>FQDN: one.one.one.one | 143444841 | 1.1.1.1 | 2022-12-06T12:03:46Z | 2023-05-16T15:26:53Z | 2023-05-16T15:26:01Z | 2130 | Linux 3.13 | DNS | 2021-03-16T09:34:16Z | host_list_detection |
>| QID: 11827<br/>TYPE: Confirmed<br/>SEVERITY: 2<br/>PORT: 80<br/>PROTOCOL: tcp<br/>FQDN: host.eu-west-1.compute.amazonaws.com<br/>SSL: 0<br/>RESULTS: X-Frame-Options or Content-Security-Policy: frame-ancestors HTTP Headers missing on port 80.<br/><br/>GET / HTTP/1.0<br/>Host: host.eu-west-1.compute.amazonaws.com<br/><br/><br/><br/>HTTP/1.1 200 OK<br/>Content-Type: text/html<br/>Last-Modified: Mon, 26 Oct 2020 17:01:12 GMT<br/>Accept-Ranges: bytes<br/>ETag: &quot;f8eec69bb9abd61:0&quot;<br/>Server: Microsoft-IIS/8.5<br/>Date: Thu, 23 Sep 2021 08:26:22 GMT<br/>Connection: keep-alive<br/>Content-Length: 701<br/><br/>X-XSS-Protection HTTP Header missing on port 80.<br/><br/>X-Content-Type-Options HTTP Header missing on port 80.<br/>STATUS: Active<br/>FIRST_FOUND_DATETIME: 2020-12-21T19:51:04Z<br/>LAST_FOUND_DATETIME: 2021-09-23T08:40:08Z<br/>TIMES_FOUND: 3<br/>LAST_TEST_DATETIME: 2021-09-23T08:40:08Z<br/>LAST_UPDATE_DATETIME: 2021-09-23T08:40:27Z<br/>IS_IGNORED: 0<br/>IS_DISABLED: 0<br/>LAST_PROCESSED_DATETIME: 2021-09-23T08:40:27Z | win-123456 | HOSTNAME: win-nk9es207bg6<br/>DOMAIN: null<br/>FQDN: null | 232347239 | 1.1.1.1 | 2020-10-21T07:33:01Z | 2021-09-23T08:40:27Z | 2021-09-23T08:40:08Z | 1129 | Windows 2012 R2 Standard | IP | 2020-12-21T19:51:04Z | host_list_detection |

