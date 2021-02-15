Cloud-based service for logs & metrics management
This integration was integrated and tested with version xx of SumoLogic
## Configure SumoLogic on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SumoLogic.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Sumo Logic URL \(region specific\), for example: https://api.us2.sumologic.com/api/ | True |
    | apiVersion | API Version | True |
    | accessID | Access ID - can be created in Sumo Logic under "Settings" | True |
    | accessKey | Access key - can be created in Sumo Logic under "Settings" | True |
    | useproxy | Use system proxy settings | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | sleepBetweenChecks | Seconds to sleep between checking for results: Polling interval for checking the results of a fetch.<br/>Note: This parameter should not be set to a value greater than fetchDelay to avoid polling for the results of the next fetch \(usually a few seconds are enough\). | True |
    | limit | Default maximum number of records to retrieve | True |
    | isFetch | Fetch incidents | False |
    | incidentType | Incident type | False |
    | fetchQuery | Run this query to fetch new events as incidents | False |
    | firstFetch | Timeframe for first fetch \(in seconds\) | False |
    | fetchDelay | Time between fetches \(in seconds\): Fetch interval. Default value is 60 seconds. The actual time will be the maximum between the selected value and the server configuration. | False |
    | maxTimeout | Default max total wait for results \(in milliseconds\) | False |
    | timeZone | Time zone of the collector to fetch from \(see detailed description\) | False |
    | fetchRecords | Fetch aggregate records \(instead of messages\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### search
***
Search SumoLogic for records that match the specified query.


#### Base Command

`search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The search query to execute. | Required | 
| from | The ISO 8601 date of the time range to start the search. For example: 2016-08-28T12:00:00. Can also be milliseconds since epoch. | Required | 
| to | The ISO 8601 date of the time range to end the search. For example: 2016-08-28T12:00:00). Can also be milliseconds since epoch. | Required | 
| limit | Maximum number of results to return from the query. Default is 100. The value specified will override the default set in the "limit" parameter. Default is 100. | Optional | 
| offset | Return results starting at this offset. should be int - by default is 0. Default is 0. | Optional | 
| timezone | The time zone if from/to is not in milliseconds. Default is UTC. See this (https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) article for a list of time zone codes. Default is UTC. | Optional | 
| maxTimeToWaitForResults | Maximum amount of time (in minutes) to wait for the search to complete. Default is 10 minutes. Default is 10. | Optional | 
| headers | A comma-separated list of table headers that are displayed in order. For example: "_blockid,_collector,_format". | Optional | 
| byReceiptTime | If "true", the search is executed using receipt time. Default is "false". Possible values are: true, false. Default is false. | Optional | 
| waitForSearchComplete | If "true", the search will wait for the query to iterate over all messages before returning results. This is useful when working with aggregate records, as otherwise the query may return partial values. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Search.Messages | unknown | The array of raw message objects. | 
| Search.Records | unknown | The array of aggregate records. | 


#### Command Example
``` !search query=_sourceCategory=macos/system from=2019-07-02T12:00:00 to=2019-07-04T16:00:00 using=SumoLogic_copy_instance_1 byReceiptTime=false limit=5```

#### Contex Example
```
{
    "Search": {
        "Messages": [
            {
                "_messageid": "-9223372036854375794", 
                "_collectorid": "162683374", 
                "_blockid": "-9223372036854745796", 
                "_source": "macOS System", 
                "_format": "t:cache:o:0:l:15:p:MMM dd HH:mm:ss", 
                "_sourcename": "/private/var/log/system.log", 
                "_sourcecategory": "macos/system", 
                "_sourcehost": "TLVMAC30YCJG5H", 
                "_messagetime": "1562255587000", 
                "_sourceid": "753908607", 
                "_raw": "Jul  4 15:53:07 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.mine.cnmaint): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.", 
                "_size": "142", 
                "_collector": "TLVMAC30YCJG5H", 
                "_messagecount": "2", 
                "_receipttime": "1562244826549", 
                "_view": ""
            }, 
            {
                "_messageid": "-9223372036854375795", 
                "_collectorid": "162683374", 
                "_blockid": "-9223372036854745797", 
                "_source": "macOS System", 
                "_format": "t:cache:o:0:l:15:p:MMM dd HH:mm:ss", 
                "_sourcename": "/private/var/log/system.log", 
                "_sourcecategory": "macos/system", 
                "_sourcehost": "TLVMAC30YCJG5H", 
                "_messagetime": "1562255551000", 
                "_sourceid": "753908607", 
                "_raw": "Jul  4 15:52:31 TLVMAC30YCJG5H syslogd[46]: ASL Sender Statistics", 
                "_size": "65", 
                "_collector": "TLVMAC30YCJG5H", 
                "_messagecount": "1", 
                "_receipttime": "1562244789356", 
                "_view": ""
            }, 
            {
                "_messageid": "-9223372036854375796", 
                "_collectorid": "162683374", 
                "_blockid": "-9223372036854745798", 
                "_source": "macOS System", 
                "_format": "t:cache:o:0:l:15:p:MMM dd HH:mm:ss", 
                "_sourcename": "/private/var/log/system.log", 
                "_sourcecategory": "macos/system", 
                "_sourcehost": "TLVMAC30YCJG5H", 
                "_messagetime": "1562255501000", 
                "_sourceid": "753908607", 
                "_raw": "Jul  4 15:51:41 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.mine.cnmaint): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.", 
                "_size": "142", 
                "_collector": "TLVMAC30YCJG5H", 
                "_messagecount": "0", 
                "_receipttime": "1562244754298", 
                "_view": ""
            }, 
            {
                "_messageid": "-9223372036854425618", 
                "_collectorid": "162683374", 
                "_blockid": "-9223372036854750767", 
                "_source": "macOS System", 
                "_format": "t:cache:o:0:l:15:p:MMM dd HH:mm:ss", 
                "_sourcename": "/private/var/log/system.log", 
                "_sourcecategory": "macos/system", 
                "_sourcehost": "TLVMAC30YCJG5H", 
                "_messagetime": "1562255066000", 
                "_sourceid": "753908607", 
                "_raw": "Jul  4 15:44:26 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.apple.quicklook[57770]): Endpoint has been activated through legacy launch(3) APIs. Please switch to XPC or bootstrap_check_in(): com.apple.quicklook", 
                "_size": "210", 
                "_collector": "TLVMAC30YCJG5H", 
                "_messagecount": "2", 
                "_receipttime": "1562244306570", 
                "_view": ""
            }, 
            {
                "_messageid": "-9223372036854375797", 
                "_collectorid": "162683374", 
                "_blockid": "-9223372036854745799", 
                "_source": "macOS System", 
                "_format": "t:cache:o:0:l:15:p:MMM dd HH:mm:ss", 
                "_sourcename": "/private/var/log/system.log", 
                "_sourcecategory": "macos/system", 
                "_sourcehost": "TLVMAC30YCJG5H", 
                "_messagetime": "1562254946000", 
                "_sourceid": "753908607", 
                "_raw": "Jul  4 15:42:26 TLVMAC30YCJG5H syslogd[46]: ASL Sender Statistics", 
                "_size": "65", 
                "_collector": "TLVMAC30YCJG5H", 
                "_messagecount": "1", 
                "_receipttime": "1562244217085", 
                "_view": ""
            }
        ]
    }
}
```



#### Human Readable Output
SumoLogic Search Messages

| blockid | collector | collectorid | format | messagecount | messageid | messagetime | raw | receipttime | size | source | sourcecategory | sourcehost | sourceid | sourcename | view | 
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
|-9223372036854740000|TLVMAC30YCJG5H|162683374|t:cache:0:l:15:p:MMM dd HH:mm:ss|2|-9223372036854370000|1562255587000|Jul 4 15:53:07 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.mine.cnmaint): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.|1562244826549|142|macOS System|macos/system|TLVMAC30YCJG5H|753908607|/private/var/log/system.log| |
|-9223372036854740000|TLVMAC30YCJG5H|162683374|t:cache:0:l:15:p:MMM dd HH:mm:ss|1|-9223372036854370000|1562255551000|Jul 4 15:52:31 TLVMAC30YCJG5H syslogd[46]: ASL Sender Statistics|1562244789356|65|macOS System|macos/system|TLVMAC30YCJG5H|753908607|/private/var/log/system.log|
|-9223372036854740000|TLVMAC30YCJG5H|162683374|t:cache:0:l:15:p:MMM dd HH:mm:ss|0|-9223372036854370000|1562255501000|Jul 4 15:51:41 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.mine.cnmaint): Service only ran for 0 seconds. Pushing respawn out by 10 seconds.|1562244754298|142|macOS System|macos/system|TLVMAC30YCJG5H|753908607|/private/var/log/system.log|
|-9223372036854750000|TLVMAC30YCJG5H|162683374|t:cache:0:l:15:p:MMM dd HH:mm:ss|2|-9223372036854420000|1562255066000|Jul 4 15:44:26 TLVMAC30YCJG5H com.apple.xpc.launchd[1] (com.apple.quicklook[57770]): Endpoint has been activated through legacy launch(3) APIs. Please switch to XPC or bootstrap_check_in():||||||||