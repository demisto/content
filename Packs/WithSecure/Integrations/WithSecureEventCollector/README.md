WithSecure event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 1.0 of WithSecure API

## Authentication Process
To create a Client ID and Client Secret, see this [documentation](https://connect.withsecure.com/getting-started/elements#:~:text=API%20deprecation%20policy.-,Getting%20client%20credentials,-To%20use%20Elements).

## Configure WithSecure Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Client ID | Client ID and Client Secret. | True |
| Client Secret |  | True |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days, 3 months, 1 year) |  | False |
| Maximum number of events per fetch, Max 1000 |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### with-secure-get-events

***
Manual command used to fetch events and display them.

#### Base Command

`with-secure-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fetch_from | The date to start collecting the events from. | Optional | 
| limit | The maximum amount of events to return. | Optional | 

#### Context Output

There is no context output for this command.

#### Command example
```!with-secure-get-events limit=2 fetch_from="90 days"```

#### Human Readable Output
### With Secure Events
|action|clientTimestamp|details|device|engine|id|organization|persistenceTimestamp|serverTimestamp|severity|
|---|---|---|---|---|---|---|---|---|---|
| created | 2023-03-15T21:58:34Z | incidentPublicId: 4550314-13<br>fingerprint: 10e34c3d5a3b531505140351b515e5d0f563b761<br>initialDetectionTimestamp: 1678917621712<br>risk: MEDIUM<br>categories: LATERAL_MOVEMENT<br>incidentId: b7ffb469-44c2-4cc0-9adb-6a3663bba393<br>clientTimestamp: 1678917514000<br>resolution: UNCONFIRMED<br>userSam: NT AUTHORITY\SYSTEM | name: WIN10-TMPLT<br>id: 45581e9d-266c-4676-9f55-1ff36f7519f9 | edr | dae559cd-37fe-3fc8-8fb1-7098c8a4d368_0 | name: Palo Alto_comp<br>id: b856d1ab-29c1-4803-b9b5-91ec7b24f94c | 2023-03-15T22:00:22.985Z | 2023-03-15T22:00:22.574Z | critical |
| created | 2023-03-15T14:01:29Z | incidentPublicId: 4550314-5<br>fingerprint: 3a653902d97ee6aa241b3e4ae18b0c01a32b97fe<br>initialDetectionTimestamp: 1678891152183<br>risk: HIGH<br>categories: SYSTEM_OR_TOOL_MISUSE<br>incidentId: 3b519e5d-addd-440f-b2b6-d8ab5bb0f4ff<br>clientTimestamp: 1678888889000<br>resolution: UNCONFIRMED<br>userSam: A-WIN81X64-TEMP\admin | name: A-WIN81X64-TEMP<br>id: fb939719-e4b5-4fb0-bfd9-3e7079833cec | edr | 1efd19d1-64db-3a56-b8fd-8da2cb87dc20_0 | name: Palo Alto_comp<br>id: b856d1ab-29c1-4803-b9b5-91ec7b24f94c | 2023-03-15T14:39:15.695Z | 2023-03-15T14:39:13.022Z | critical |

