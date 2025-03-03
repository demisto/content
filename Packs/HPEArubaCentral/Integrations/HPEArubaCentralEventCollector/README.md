This is the Aruba Central event collector integration for Cortex XSIAM.

## Configure HPE Aruba Central Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Domain URL for API gateway access | True |
| Client ID || True |
| Client Secret || True |
| Customer ID || True |
| Username || True |
| Password || True |
| Fetch networking events | Whether to fetch networking events or only audit logs. | False |
| The maximum number of audit events per fetch | Default - 100 | False |
| The maximum number of networking events per fetch | Default - 5000 | False |
| Trust any certificate (not secure) || False |
| Use system proxy settings || False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aruba-central-get-events

***
Gets events from Aruba Central.

#### Base Command

`aruba-central-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| limit | Maximum number of results to return. | Required | 
| from_date | Date from which to get events. Default is 3 hours prior. | Optional | 

#### Command Example

```!aruba-central-get-events limit=5 should_push_events=false from_date='09-15-2024'```

#### Context Output

There is no context output for this command.

#### Human Readable Output

>### Audit Events
>
>| cid | classification | cname | description | device_type | gid | has_details | id | ip_addr | msp_id | target | ts | user |
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
>| 50b8aef1ec00000000004ec069d890c4 | Configuration | Financial, Inc. | Swarm configuration sync successful | iap | 8 | false | audit_trail_2024_9,AZHzPN000000c5NiQdg- | 0.0.0.0 | STANDALONE | PHL000000K | 1726362738 | System |
>| 50b8aef1ec00000000004ec069d890c4 | Configuration | Financial, Inc. | Swarm configuration sync successful | iap | 8 | false | audit_trail_2024_9,AZHzPR000000ByoC37es | 0.0.0.0 | STANDALONE | PHL000000K | 1726362751 | System |
>| 50b8aef1ec00000000004ec069d890c4 | Configuration | Financial, Inc. | Point configuration sync successful | iap | 28 | false | audit_trail_2024_9,AZH0C000000vzoci09Qm | 0.0.0.0 | STANDALONE | CN00000CHM | 1726376250 | System |
>| 50b8aef1ec00000000004ec069d890c4 | Configuration | Financial, Inc. | Swarm configuration sync successful | iap | 69 | false | audit_trail_2024_9,AZH00000000nKZfijDJe | 0.0.0.0 | STANDALONE | CN00000HWY | 1726389270 | System |
>| 50b8aef1ec00000000004ec069d890c4 | Configuration | Financial, Inc. | Swarm configuration sync successful | iap | 69 | false | audit_trail_2024_9,AZH16000000zKyye7zCq | 0.0.0.0 | STANDALONE | PH000001TR | 1726407685 | System |

>### Networking Events
>
>| bssid | client_mac | description | device_mac | device_serial | device_type | event_type | event_uuid | group_name | has_rowdetail | hostname | labels | level | number | sites | timestamp |
>| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
>|  |  | ports:  port 46 is now off-line | 64:e8:00:00:5a:80 | TW00K000HW | SWITCH | Ports | 59b61831-7c71-1234-acf3-6f7c65d38fd7 | 003 - 2021 Standard NAC | false | IDFNT-000N01-ANSW02P3 | {'id': 220, 'name': 'Pac'} | INFO | 77 | {'id': 37, 'name': 'ID FNT Meridian 01 - 220618'} | 1726358400000 |
>|  |  | ports:  ST1-CMDR: port 1/42 is now off-line | d4:e0:00:00:58:80 | SG000YZ00V | SWITCH | Ports | e1c8c68c-0eea-1234-a296-a77e67b9bf37 | CT - 10 S LaSalle | false | ILCTT-C00001-ANSW31P2 | {'id': 221, 'name': 'Mid'} | INFO | 77 | {'id': 25, 'name': 'IL 01 - 904'} | 1726358400000 |
>|  |  | There are no RADIUS servers configured. | 64:e8:00:00:37:00 | SG00J002CL | SWITCH | RADIUS | 0b72cc8c-7ddb-1234-99a6-6669b3cf2a31 | 003 - 2021 Standard NAC | false | NEFNT-O00001-ANSW03P2 | {'id': 125, 'name': 'Corp_IT_Operations'} | Informational | 434 | {'id': 18, 'name': 'NE FNTG 01 - 3008'} | 1726358400000 |
>|  |  | Mac Authentication failed for client b0:5c:da:9f:00:00 against server , 0.0.0.0.  Failure reason: Missing Radius Server configuration | 64:e8:00:00:37:00 | SG00JQ000L | SWITCH | | 450000c6-1234-4000-9c88-a162979ea016 | 003 - 2021 Standard NAC | false | NEFNT-O00001-ANSW03P2 | {'id': 125, 'name': 'Corp_IT_Operations'} | Minor | 43025 | {'id': 158, 'name': 'NE FNTG 01 - 300820'} | 1726358400000 |
>|  |  | There are no RADIUS servers configured. | 64:e8:00:00:37:00 | SG00JQ000L | SWITCH | RADIUS | 9bba8889-5aee-1234-808e-dda306e108b7 | 003 - 2021 Standard NAC | false | NEFNT-O00001-ANSW03P2 | {'id': 125, 'name': 'Corp_IT_Operations'} | Informational | 436 | {'id': 15, 'name': 'NE FNTG 01 - 3020'} | 1726358401000 |