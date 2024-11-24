You can use this integration to automate different Camlytics surveillance analysis actions.
This integration was integrated and tested with version 2.2.5 of Camlytics.

## Configure Camlytics in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### camlytics-get-channels
***
Retrieve video channels


#### Base Command

`camlytics-get-channels`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Camlytics.Channels.channel_id | String | The channel ID. | 
| Camlytics.Channels.name | String | The channel name. | 
| Camlytics.Channels.type | String | The channel type. | 
| Camlytics.Channels.stream_uri | String | The channel stream_ur. | 
| Camlytics.Channels.login | String | The channel login. | 
| Camlytics.Channels.password | String | The channel password. | 
| Camlytics.Channels.uri | String | The channel uri. | 
| Camlytics.Channels.profile_name | String | The channel profile. | 
| Camlytics.Channels.profile_token | String | The channel profile token. | 

#### Command example
```!camlytics-get-channels```
#### Context Example
```json
{
    "Camlytics": {
        "Channels": [
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "login": null,
                "name": "Springs",
                "password": null,
                "profile_name": "none",
                "profile_token": "",
                "stream_uri": "C:\\Users\\hussain\\Desktop\\Test Video.mp4",
                "type": "File",
                "uri": "http://localhost/"
            },
            {
                "channel_id": "8c27e658-cfee-4801-b1f7-29626ce45afc",
                "login": null,
                "name": "Video file",
                "password": null,
                "profile_name": "none",
                "profile_token": "",
                "stream_uri": "C:\\Users\\hussain\\Desktop\\Test Video - Copy.mp4",
                "type": "File",
                "uri": "http://localhost/"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|channel_id|login|name|password|profile_name|profile_token|stream_uri|type|uri|
>|---|---|---|---|---|---|---|---|---|
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | Springs |  | none |  | C:\Users\hussain\Desktop\Test Video.mp4 | File | http://localhost/ |
>| 8c27e658-cfee-4801-b1f7-29626ce45afc |  | Video file |  | none |  | C:\Users\hussain\Desktop\Test Video - Copy.mp4 | File | http://localhost/ |


### camlytics-get-events-totals-by-rule
***
Retrieve video analytics events totals grouped by calibration rules, these rules can be defined using zones and lines to set areas where different camera events will be generated. For example, you can add zone where you want signalize all of all entered objects, line where you want to count people, etc.


#### Base Command

`camlytics-get-events-totals-by-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channelid | The channel ID. | Optional | 
| sincetime | The since time. | Optional | 
| untiltime | The until time. | Optional | 
| origin | The origin that generated the events. For example, if you want to display only vehicles events and skip pedestrians in your report, choose Vehicle. Possible values are: Pedestrians, Vehicle, Uknown. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Camlytics.EventsTotalsRule.channel_id | String | The channel ID. | 
| Camlytics.EventsTotalsRule.rule_count | Number | The rule count. | 
| Camlytics.EventsTotalsRule.rule_id | String | The rule ID. | 
| Camlytics.EventsTotalsRule.rule_name | String | The rule name. | 

#### Command example
```!camlytics-get-events-totals-by-rule```
#### Context Example
```json
{
    "Camlytics": {
        "EventsTotalsRule": [
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "rule_count": 47,
                "rule_id": "-1",
                "rule_name": ""
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "rule_count": 4,
                "rule_id": "18413998-0ab9-44ba-a90c-5d0ce844abff",
                "rule_name": "Motion detection"
            },
            {
                "channel_id": "8c27e658-cfee-4801-b1f7-29626ce45afc",
                "rule_count": 9,
                "rule_id": "-1",
                "rule_name": ""
            },
            {
                "channel_id": "8c27e658-cfee-4801-b1f7-29626ce45afc",
                "rule_count": 1,
                "rule_id": "2ec821ed-3fb5-4b0b-aab9-3f600c05914c",
                "rule_name": "Motion detection"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|channel_id|rule_count|rule_id|rule_name|
>|---|---|---|---|
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 | 47 | -1 |  |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 | 4 | 18413998-0ab9-44ba-a90c-5d0ce844abff | Motion detection |
>| 8c27e658-cfee-4801-b1f7-29626ce45afc | 9 | -1 |  |
>| 8c27e658-cfee-4801-b1f7-29626ce45afc | 1 | 2ec821ed-3fb5-4b0b-aab9-3f600c05914c | Motion detection |


### camlytics-get-events-totals-by-type
***
Retrieve video analytics events totals grouped by analytics event type. For example: ObjectAppear, Tailgating, Sabotage and TripwireCrossed.


#### Base Command

`camlytics-get-events-totals-by-type`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channelid | The channel ID. | Optional | 
| sincetime | The since time. | Optional | 
| untiltime | The until time. | Optional | 
| origin | The origin that generated the events. For example, if you want to display only vehicles events and skip pedestrians in your report, choose Vehicle. Possible values are: Pedestrians, Vehicle, Uknown. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Camlytics.EventsTotalsType.channel_id | String | The channel ID. | 
| Camlytics.EventsTotalsType.type | String | The event type. For example: ObjectAppear, Tailgating, Sabotage and TripwireCrossed. | 
| Camlytics.EventsTotalsType.type_count | Number | The type count. | 

#### Command example
```!camlytics-get-events-totals-by-type channelid=09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 origin=Pedestrian```
#### Context Example
```json
{
    "Camlytics": {
        "EventsTotalsType": [
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "type": "ObjectAppear",
                "type_count": 4
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "type": "ObjectDisappear",
                "type_count": 3
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|channel_id|type|type_count|
>|---|---|---|
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 | ObjectAppear | 4 |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 | ObjectDisappear | 3 |


### camlytics-get-events
***
Retrieve video analytics events ordered by event id.


#### Base Command

`camlytics-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channelid | The channel ID. | Optional | 
| sinceid | The since ID. | Optional | 
| sincetime | The since time. | Optional | 
| untilid | The until ID. | Optional | 
| untiltime | The until time. | Optional | 
| limit | The limit. | Optional | 
| order | The order. | Optional | 
| timeout | The timeout. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Camlytics.Events.event_id | String | The event ID. | 
| Camlytics.Events.type | String | The event type. | 
| Camlytics.Events.time | String | The event time. | 
| Camlytics.Events.timestamp | String | The event timestamp. | 
| Camlytics.Events.channel_id | String | The event channel id. | 
| Camlytics.Events.channel_name | String | The event channel name. | 
| Camlytics.Events.object_id | String | The event object id. | 
| Camlytics.Events.origin | String | The event origin. | 
| Camlytics.Events.rule_id | String | The event rule id. | 
| Camlytics.Events.rule_name | String | The event rule name. | 
| Camlytics.Events.snapshot_path | String | The event snapshot path. | 
| Camlytics.Events.recording_path | String | The event recording path. | 
| Camlytics.Events.video_file_name | String | The event video file name. | 
| Camlytics.Events.video_file_time | Date | The event video file time. | 

#### Command example
```!camlytics-get-events channelid="09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9" limit="10"```
#### Context Example
```json
{
    "Camlytics": {
        "Events": [
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "channel_name": null,
                "event_id": 70,
                "object_id": "-1",
                "origin": "Unknown",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-19T16:22:25.4330000",
                "timestamp": "1.877",
                "type": "Sabotage",
                "video_file_name": "Test Video.mp4",
                "video_file_time": "2022-01-19T16:21:11.8770000"
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "channel_name": null,
                "event_id": 71,
                "object_id": "1",
                "origin": "Unknown",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-19T16:22:32.5630000",
                "timestamp": "3.545",
                "type": "ObjectAppear",
                "video_file_name": "Test Video.mp4",
                "video_file_time": "2022-01-19T16:21:13.5470000"
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "channel_name": null,
                "event_id": 72,
                "object_id": "1",
                "origin": "Unknown",
                "recording_path": "",
                "rule_id": "18413998-0ab9-44ba-a90c-5d0ce844abff",
                "rule_name": "Motion detection",
                "snapshot_path": "C:\\Users\\hussain\\AppData\\Roaming\\Camlytics\\Data\\09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9\\Snapshots\\MotionInRegionOn 1 2022-01-19 16-21-13-546.jpg",
                "time": "2022-01-19T16:22:32.5630000",
                "timestamp": "3.545",
                "type": "MotionInRegionOn",
                "video_file_name": "Test Video.mp4",
                "video_file_time": "2022-01-19T16:21:13.5470000"
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "channel_name": null,
                "event_id": 73,
                "object_id": "2",
                "origin": "Unknown",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-19T16:22:32.3670000",
                "timestamp": "3.504",
                "type": "ObjectAppear",
                "video_file_name": "Test Video.mp4",
                "video_file_time": "2022-01-19T16:21:13.5030000"
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "channel_name": null,
                "event_id": 74,
                "object_id": "3",
                "origin": "Unknown",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-19T16:22:32.4470000",
                "timestamp": "3.67",
                "type": "ObjectAppear",
                "video_file_name": "Test Video.mp4",
                "video_file_time": "2022-01-19T16:21:13.6700000"
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "channel_name": null,
                "event_id": 75,
                "object_id": "3",
                "origin": "Unknown",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-19T16:22:33.6030000",
                "timestamp": "5.005",
                "type": "ObjectDisappear",
                "video_file_name": "Test Video.mp4",
                "video_file_time": "2022-01-19T16:21:15.0070000"
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "channel_name": null,
                "event_id": 76,
                "object_id": "2",
                "origin": "Unknown",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-19T16:22:33.6030000",
                "timestamp": "5.005",
                "type": "ObjectDisappear",
                "video_file_name": "Test Video.mp4",
                "video_file_time": "2022-01-19T16:21:15.0070000"
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "channel_name": null,
                "event_id": 77,
                "object_id": "5",
                "origin": "Vehicle",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-19T16:22:32.8100000",
                "timestamp": "4.213",
                "type": "ObjectAppear",
                "video_file_name": "Test Video.mp4",
                "video_file_time": "2022-01-19T16:21:14.2130000"
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "channel_name": null,
                "event_id": 78,
                "object_id": "4",
                "origin": "Vehicle",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-19T16:22:32.1430000",
                "timestamp": "3.545",
                "type": "ObjectAppear",
                "video_file_name": "Test Video.mp4",
                "video_file_time": "2022-01-19T16:21:13.5470000"
            },
            {
                "channel_id": "09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9",
                "channel_name": null,
                "event_id": 79,
                "object_id": "1",
                "origin": "Unknown",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-19T16:22:33.8930000",
                "timestamp": "5.589",
                "type": "ObjectDisappear",
                "video_file_name": "Test Video.mp4",
                "video_file_time": "2022-01-19T16:21:15.5900000"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|channel_id|channel_name|event_id|object_id|origin|recording_path|rule_id|rule_name|snapshot_path|time|timestamp|type|video_file_name|video_file_time|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | 70 | -1 | Unknown |  | -1 |  |  | 2022-01-19T16:22:25.4330000 | 1.877 | Sabotage | Test Video.mp4 | 2022-01-19T16:21:11.8770000 |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | 71 | 1 | Unknown |  | -1 |  |  | 2022-01-19T16:22:32.5630000 | 3.545 | ObjectAppear | Test Video.mp4 | 2022-01-19T16:21:13.5470000 |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | 72 | 1 | Unknown |  | 18413998-0ab9-44ba-a90c-5d0ce844abff | Motion detection | C:\Users\hussain\AppData\Roaming\Camlytics\Data\09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9\Snapshots\MotionInRegionOn 1 2022-01-19 16-21-13-546.jpg | 2022-01-19T16:22:32.5630000 | 3.545 | MotionInRegionOn | Test Video.mp4 | 2022-01-19T16:21:13.5470000 |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | 73 | 2 | Unknown |  | -1 |  |  | 2022-01-19T16:22:32.3670000 | 3.504 | ObjectAppear | Test Video.mp4 | 2022-01-19T16:21:13.5030000 |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | 74 | 3 | Unknown |  | -1 |  |  | 2022-01-19T16:22:32.4470000 | 3.67 | ObjectAppear | Test Video.mp4 | 2022-01-19T16:21:13.6700000 |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | 75 | 3 | Unknown |  | -1 |  |  | 2022-01-19T16:22:33.6030000 | 5.005 | ObjectDisappear | Test Video.mp4 | 2022-01-19T16:21:15.0070000 |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | 76 | 2 | Unknown |  | -1 |  |  | 2022-01-19T16:22:33.6030000 | 5.005 | ObjectDisappear | Test Video.mp4 | 2022-01-19T16:21:15.0070000 |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | 77 | 5 | Vehicle |  | -1 |  |  | 2022-01-19T16:22:32.8100000 | 4.213 | ObjectAppear | Test Video.mp4 | 2022-01-19T16:21:14.2130000 |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | 78 | 4 | Vehicle |  | -1 |  |  | 2022-01-19T16:22:32.1430000 | 3.545 | ObjectAppear | Test Video.mp4 | 2022-01-19T16:21:13.5470000 |
>| 09ed1f1f-63fe-41d9-8e4a-f4909f94f2b9 |  | 79 | 1 | Unknown |  | -1 |  |  | 2022-01-19T16:22:33.8930000 | 5.589 | ObjectDisappear | Test Video.mp4 | 2022-01-19T16:21:15.5900000 |
