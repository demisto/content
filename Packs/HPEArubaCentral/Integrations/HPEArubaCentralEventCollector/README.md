This is the Aruba Central event collector integration for Cortex XSIAM.

## Configure HPE Aruba Central Event Collector in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| **Server URL** | The region-specific Base URL for the Aruba Central API Gateway. | True |
| **Authentication Method** | The authentication method to use. "Access Token": paste the token JSON downloaded from the Aruba Central UI. "Basic Auth": provide a Username, Password, and Customer ID. | False |
| **Client ID** | The unique identifier for your API application registered in Aruba Central. | True |
| **Client Secret** | The secret key associated with your Client ID for API authentication. | True |
| **Access Token (JSON)** | The full token JSON downloaded from the Aruba Central UI (click the "Download Token" button and paste it here). The integration reads the `refresh_token` from it and refreshes access tokens automatically with no username/password. Required when the Authentication Method is "Access Token". | False |
| **Customer ID** | The unique identifier for your Aruba Central account. Required only when the Authentication Method is "Basic Auth". | False |
| **Username** | The username of an Aruba Central account with at least read-only privileges. Required only when the Authentication Method is "Basic Auth". | False |
| **Password** | The password associated with the specified Aruba Central username. Required only when the Authentication Method is "Basic Auth". | False |
| **Fetch Events** | Select this to enable fetching events into Cortex. | False |
| **Events Fetch Interval** | The interval, in minutes, between event fetches. | False |
| **Fetch networking events** | Select this to fetch networking events in addition to audit logs. If cleared, the collector will only fetch audit logs. | False |
| **The maximum number of audit events per fetch** | The maximum number of audit events to pull in a single fetch. The default is `100`. | False |
| **The maximum number of networking events per fetch** | The maximum number of networking events to pull in a single fetch. The default is `5000`. | False |
| **Trust any certificate (not secure)** | Select this to bypass certificate validation. Use this only for testing or in trusted, isolated environments. | False |

## How to Find Required Parameters

You can find most of the required API credentials within your HPE Aruba Central account.

1. Log in to your **Aruba Central** account.
2. Navigate to the **Global Settings** menu (or the equivalent management scope).
3. Select **API Gateway**.

From this section, you can retrieve the following information:

* **Access Token URL:** Found on the **APIs** tab.
* **Customer ID:** Found on the **APIs** tab.
* **Server URL:** This is the base domain of your Aruba Central portal (e.g., `https://app-uswest4.central.arubanetworks.com`).
* **Client ID & Client Secret:** Found on the **My Apps** tab. Select the application you created for XSOAR to view its details.

**User Credentials:**

* **Username & Password:** These are the credentials for the Aruba Central user account that you used to generate the API application (Client ID and Secret). This account must have at least read-only privileges.

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

### aruba-auth-test

***
Use this command to test the connectivity of the HPE Aruba Central instance.

#### Base Command

`aruba-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

## Troubleshooting

### Token expiration (Access Token method)

Access tokens are valid for 2 hours, and refresh tokens are valid for 15 days. If an access token is not renewed for 15 days (meaning the refresh token is unused for 15 days), Aruba Central removes the token. At this point, a new token must be generated either by going to the API Gateway UI (clicking the "Download Token" button and pasting the new token JSON here) or by using the OAuth API (Basic Auth method).
