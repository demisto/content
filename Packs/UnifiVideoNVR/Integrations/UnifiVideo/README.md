
### unifivideo-get-camera-list

***
Gets the list of cameras bound with the NVR.

#### Base Command

`unifivideo-get-camera-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UnifiVideo.Cameras | Unknown | The camera list. | 
### unifivideo-get-snapshot

***
The name of the camera to take the snapshot from. If empty then all camera snapshots will be taken.

#### Base Command

`unifivideo-get-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| camera_name | The name of the camera. | Required | 

#### Context Output

There is no context output for this command.
### unifivideo-get-recording

***
Download a recording to file.

#### Base Command

`unifivideo-get-recording`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| recording_id | The id of the recording. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UnifiVideo.Recordings | Unknown | The recording list. | 
### unifivideo-set-recording-settings

***
Set the recording settings.

#### Base Command

`unifivideo-set-recording-settings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| camera_name | The camera name. | Required | 
| rec_set | Recording setting, motion,fulltime or disable. Possible values are: fulltime, motion, disable. Default is motion. | Required | 

#### Context Output

There is no context output for this command.
### unifivideo-ir-leds

***
Turn ON or OFF the camera Infra-Red LED.

#### Base Command

`unifivideo-ir-leds`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| camera_name | The camera name. | Required | 
| ir_leds | The Infra-Red LED mode. Possible values are: auto, on, off. Default is auto. | Required | 

#### Context Output

There is no context output for this command.
### unifivideo-get-recording-list

***
Get the list of all recordings.

#### Base Command

`unifivideo-get-recording-list`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### unifivideo-get-snapshot-at-frame

***
Get a snapshot from video file based on the frame number.

#### Base Command

`unifivideo-get-snapshot-at-frame`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryid | File entryID of the video file. | Required | 
| frame | Frame to take from the video. | Required | 

#### Context Output

There is no context output for this command.
### unifivideo-get-recording-snapshot

***
Get the recording snapshot (at frame) based on the recording id.

#### Base Command

`unifivideo-get-recording-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| frame | The frame to snapshot. Default is 150. | Required | 
| recording_id | the ubnt_id of the recording. | Required | 

#### Context Output

There is no context output for this command.
### unifivideo-get-recording-motion-snapshot

***
Gets the frame snapshot that has triggered the motion event.

#### Base Command

`unifivideo-get-recording-motion-snapshot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| recording_id | the ubnt_id of the recording. | Required | 

#### Context Output

There is no context output for this command.