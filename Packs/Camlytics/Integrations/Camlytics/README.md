You can use this integration to automate different Camlytics surveillance analysis actions.
This integration was integrated and tested with version 2.2.5 of Camlytics

## Configure Camlytics on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Camlytics.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "login": null,
                "name": "Video file",
                "password": null,
                "profile_name": "none",
                "profile_token": "",
                "stream_uri": "C:\\Users\\hussain\\Desktop\\Human.mp4",
                "type": "File",
                "uri": "http://localhost/"
            },
            {
                "channel_id": "8eed552b-ed50-47b1-a1d0-4180484848a0",
                "login": null,
                "name": "Video file",
                "password": null,
                "profile_name": "none",
                "profile_token": "",
                "stream_uri": "C:\\Users\\hussain\\Desktop\\Human2.mp4",
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
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 |  | Video file |  | none |  | C:\Users\hussain\Desktop\Human.mp4 | File | http://localhost/ |
>| 8eed552b-ed50-47b1-a1d0-4180484848a0 |  | Video file |  | none |  | C:\Users\hussain\Desktop\Human2.mp4 | File | http://localhost/ |


### camlytics-get-events-totals-by-rule
***
Retrieve video analytics events totals grouped by rules (zones, lines).


#### Base Command

`camlytics-get-events-totals-by-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channelid | The channel ID. | Optional | 
| sincetime | The since time. | Optional | 
| untiltime | The until time. | Optional | 
| origin | The origin. | Optional | 


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
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "rule_count": 4,
                "rule_id": "-1",
                "rule_name": ""
            },
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "rule_count": 3,
                "rule_id": "e953f9ef-3138-4052-887b-235eb81c00d4",
                "rule_name": "Motion detection"
            },
            {
                "channel_id": "8eed552b-ed50-47b1-a1d0-4180484848a0",
                "rule_count": 11,
                "rule_id": "-1",
                "rule_name": ""
            },
            {
                "channel_id": "8eed552b-ed50-47b1-a1d0-4180484848a0",
                "rule_count": 3,
                "rule_id": "4fe7338f-6f85-441a-a200-f383d814b0ee",
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
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 | 4 | -1 |  |
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 | 3 | e953f9ef-3138-4052-887b-235eb81c00d4 | Motion detection |
>| 8eed552b-ed50-47b1-a1d0-4180484848a0 | 11 | -1 |  |
>| 8eed552b-ed50-47b1-a1d0-4180484848a0 | 3 | 4fe7338f-6f85-441a-a200-f383d814b0ee | Motion detection |


### camlytics-get-events-totals-by-type
***
Retrieve video analytics events totals grouped by type.


#### Base Command

`camlytics-get-events-totals-by-type`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channelid | The channel ID. | Optional | 
| sincetime | The since time. | Optional | 
| untiltime | The until time. | Optional | 
| origin | The origin. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Camlytics.EventsTotalsType.channel_id | String | The channel ID. | 
| Camlytics.EventsTotalsType.type | String | The event type. | 
| Camlytics.EventsTotalsType.type_count | Number | The type count. | 

#### Command example
```!camlytics-get-events-totals-by-type channelid=b7ad2693-c9bf-42a7-9cfa-7289ca30a708 origin=Pedestrian```
#### Context Example
```json
{
    "Camlytics": {
        "EventsTotalsType": [
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "type": "MotionInRegionOn",
                "type_count": 2
            },
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "type": "ObjectAppear",
                "type_count": 3
            },
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "type": "ObjectDisappear",
                "type_count": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|channel_id|type|type_count|
>|---|---|---|
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 | MotionInRegionOn | 2 |
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 | ObjectAppear | 3 |
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 | ObjectDisappear | 1 |


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
```!camlytics-get-events channelid="b7ad2693-c9bf-42a7-9cfa-7289ca30a708" limit="10"```
#### Context Example
```json
{
    "Camlytics": {
        "Events": [
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "channel_name": null,
                "event_id": 14,
                "object_id": "1",
                "origin": "Pedestrian",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-12T10:34:54.6870000",
                "timestamp": "1.533",
                "type": "ObjectAppear",
                "video_file_name": "Human.mp4",
                "video_file_time": "2022-01-11T21:23:50.4930000"
            },
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "channel_name": null,
                "event_id": 15,
                "object_id": "1",
                "origin": "Pedestrian",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-12T10:35:07.8400000",
                "timestamp": "7.333",
                "type": "ObjectAppear",
                "video_file_name": "Human.mp4",
                "video_file_time": "2022-01-11T21:23:56.2930000"
            },
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "channel_name": null,
                "event_id": 16,
                "object_id": "1",
                "origin": "Pedestrian",
                "recording_path": "",
                "rule_id": "e953f9ef-3138-4052-887b-235eb81c00d4",
                "rule_name": "Motion detection",
                "snapshot_path": "C:\\Users\\hussain\\AppData\\Roaming\\Camlytics\\Data\\b7ad2693-c9bf-42a7-9cfa-7289ca30a708\\Snapshots\\MotionInRegionOn 1 2022-01-11 21-23-56-293.jpg",
                "time": "2022-01-12T10:35:07.8400000",
                "timestamp": "7.333",
                "type": "MotionInRegionOn",
                "video_file_name": "Human.mp4",
                "video_file_time": "2022-01-11T21:23:56.2930000"
            },
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "channel_name": null,
                "event_id": 17,
                "object_id": "1",
                "origin": "Pedestrian",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-12T10:35:19.7270000",
                "timestamp": "1.533",
                "type": "ObjectAppear",
                "video_file_name": "Human.mp4",
                "video_file_time": "2022-01-11T21:23:50.4930000"
            },
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "channel_name": null,
                "event_id": 18,
                "object_id": "1",
                "origin": "Pedestrian",
                "recording_path": "",
                "rule_id": "e953f9ef-3138-4052-887b-235eb81c00d4",
                "rule_name": "Motion detection",
                "snapshot_path": "C:\\Users\\hussain\\AppData\\Roaming\\Camlytics\\Data\\b7ad2693-c9bf-42a7-9cfa-7289ca30a708\\Snapshots\\MotionInRegionOn 1 2022-01-11 21-23-50-493.jpg",
                "time": "2022-01-12T10:35:19.7270000",
                "timestamp": "1.533",
                "type": "MotionInRegionOn",
                "video_file_name": "Human.mp4",
                "video_file_time": "2022-01-11T21:23:50.4930000"
            },
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "channel_name": null,
                "event_id": 19,
                "object_id": "1",
                "origin": "Pedestrian",
                "recording_path": "",
                "rule_id": "-1",
                "rule_name": "",
                "snapshot_path": "",
                "time": "2022-01-12T10:35:23.9600000",
                "timestamp": "9.067",
                "type": "ObjectDisappear",
                "video_file_name": "Human.mp4",
                "video_file_time": "2022-01-11T21:23:58.0270000"
            },
            {
                "channel_id": "b7ad2693-c9bf-42a7-9cfa-7289ca30a708",
                "channel_name": null,
                "event_id": 20,
                "object_id": "-1",
                "origin": "Unknown",
                "recording_path": "",
                "rule_id": "e953f9ef-3138-4052-887b-235eb81c00d4",
                "rule_name": "Motion detection",
                "snapshot_path": "",
                "time": "2022-01-12T10:35:25.1000000",
                "timestamp": "18",
                "type": "MotionInRegionOff",
                "video_file_name": "Human.mp4",
                "video_file_time": "2022-01-11T21:24:06.9600000"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|channel_id|channel_name|event_id|object_id|origin|recording_path|rule_id|rule_name|snapshot_path|time|timestamp|type|video_file_name|video_file_time|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 |  | 14 | 1 | Pedestrian |  | -1 |  |  | 2022-01-12T10:34:54.6870000 | 1.533 | ObjectAppear | Human.mp4 | 2022-01-11T21:23:50.4930000 |
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 |  | 15 | 1 | Pedestrian |  | -1 |  |  | 2022-01-12T10:35:07.8400000 | 7.333 | ObjectAppear | Human.mp4 | 2022-01-11T21:23:56.2930000 |
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 |  | 16 | 1 | Pedestrian |  | e953f9ef-3138-4052-887b-235eb81c00d4 | Motion detection | C:\Users\hussain\AppData\Roaming\Camlytics\Data\b7ad2693-c9bf-42a7-9cfa-7289ca30a708\Snapshots\MotionInRegionOn 1 2022-01-11 21-23-56-293.jpg | 2022-01-12T10:35:07.8400000 | 7.333 | MotionInRegionOn | Human.mp4 | 2022-01-11T21:23:56.2930000 |
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 |  | 17 | 1 | Pedestrian |  | -1 |  |  | 2022-01-12T10:35:19.7270000 | 1.533 | ObjectAppear | Human.mp4 | 2022-01-11T21:23:50.4930000 |
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 |  | 18 | 1 | Pedestrian |  | e953f9ef-3138-4052-887b-235eb81c00d4 | Motion detection | C:\Users\hussain\AppData\Roaming\Camlytics\Data\b7ad2693-c9bf-42a7-9cfa-7289ca30a708\Snapshots\MotionInRegionOn 1 2022-01-11 21-23-50-493.jpg | 2022-01-12T10:35:19.7270000 | 1.533 | MotionInRegionOn | Human.mp4 | 2022-01-11T21:23:50.4930000 |
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 |  | 19 | 1 | Pedestrian |  | -1 |  |  | 2022-01-12T10:35:23.9600000 | 9.067 | ObjectDisappear | Human.mp4 | 2022-01-11T21:23:58.0270000 |
>| b7ad2693-c9bf-42a7-9cfa-7289ca30a708 |  | 20 | -1 | Unknown |  | e953f9ef-3138-4052-887b-235eb81c00d4 | Motion detection |  | 2022-01-12T10:35:25.1000000 | 18 | MotionInRegionOff | Human.mp4 | 2022-01-11T21:24:06.9600000 |

