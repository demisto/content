"Intel 471's Actors feed is an actor-centric intelligence feature.
It combines both a field-based intelligence collection and a headquartered-based intelligence analysis component.
This feed allows getting data out of closed sources (typically referred to as the deep and dark web) where threat actors collaborate, communicate, and plan cyber attacks."
## Configure Intel471 Actors Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| credentials | Username | True |
| feed | Fetch indicators | False |
| feedReputation | Indicator Reputation | False |
| feedReliability | Source Reliability | True |
| tlp_color | Traffic Light Protocol Color | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| actor | Free text actor search \(all fields included\) | False |
| fetch_time | First fetch timestamp \(`<number>` `<time unit>`, e.g., 12 hours, 7 days\) | False |
| feedTags | Tags |  |
| feedBypassExclusionList | Bypass exclusion list | False |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### intel471-actors-get-indicators
***
Gets the feed indicators.


#### Base Command

`intel471-actors-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default is 50. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!intel471-actors-get-indicators limit=10```


>### Indicators
>|value|type|rawJSON|
>|---|---|---|
>| h.m.15 | STIX Threat Actor | lastUpdated: 1611219975088<br/>handles: h.m.15<br/>links: {"forums": [{"name": "unknowncheats", "actorHandle": "h.m.15", "uid": "4671aeaf49c792689533b00664a5c3ef"}], "forumTotalCount": 1, "instantMessageChannelTotalCount": 0, "forumPrivateMessageTotalCount": 0, "reportTotalCount": 0, "instantMessageTotalCount": 0, "instantMessageServerTotalCount": 0, "forumPostTotalCount": 1}<br/>activeFrom: 1078774740000<br/>activeUntil: 1078774740000<br/>uid: 7d1da0f4f0b26f3fb777fdd662c5cc68 |
>| bradleykins | STIX Threat Actor | lastUpdated: 1611219676493<br/>handles: bradleykins<br/>links: {"forums": [{"name": "unknowncheats", "actorHandle": "bradleykins", "uid": "4671aeaf49c792689533b00664a5c3ef"}], "forumTotalCount": 1, "instantMessageChannelTotalCount": 0, "forumPrivateMessageTotalCount": 0, "reportTotalCount": 0, "instantMessageTotalCount": 0, "instantMessageServerTotalCount": 0, "forumPostTotalCount": 1}<br/>activeFrom: 1080079020000<br/>activeUntil: 1080079020000<br/>uid: b6c4bf36d66d7892244bd56572704982 |
>| Eleethal | STIX Threat Actor | lastUpdated: 1611299774949<br/>handles: Eleethal<br/>links: {"forums": [{"name": "unknowncheats", "actorHandle": "Eleethal", "uid": "4671aeaf49c792689533b00664a5c3ef"}], "forumTotalCount": 1, "instantMessageChannelTotalCount": 0, "forumPrivateMessageTotalCount": 0, "reportTotalCount": 0, "instantMessageTotalCount": 0, "instantMessageServerTotalCount": 0, "forumPostTotalCount": 502}<br/>activeFrom: 1090467720000<br/>activeUntil: 1090467720000<br/>uid: 482c379b7a0bda6574bf0b5ca63532e6 |
>| jag4life | STIX Threat Actor | lastUpdated: 1611214277667<br/>handles: jag4life<br/>links: {"forums": [{"name": "unknowncheats", "actorHandle": "jag4life", "uid": "4671aeaf49c792689533b00664a5c3ef"}], "forumTotalCount": 1, "instantMessageChannelTotalCount": 0, "forumPrivateMessageTotalCount": 0, "reportTotalCount": 0, "instantMessageTotalCount": 0, "instantMessageServerTotalCount": 0, "forumPostTotalCount": 1}<br/>activeFrom: 1098304440000<br/>activeUntil: 1098304440000<br/>uid: 0e6cee474206abe743b748ca36fc62eb |
>| ice-killer | STIX Threat Actor | lastUpdated: 1611246675557<br/>handles: ice-killer<br/>links: {"forums": [{"name": "mazafaka", "actorHandle": "ice-killer", "uid": "fc221309746013ac554571fbd180e1c8"}], "forumTotalCount": 1, "instantMessageChannelTotalCount": 0, "forumPrivateMessageTotalCount": 0, "reportTotalCount": 0, "instantMessageTotalCount": 0, "instantMessageServerTotalCount": 0, "forumPostTotalCount": 28}<br/>activeFrom: 1099041900000<br/>activeUntil: 1099041900000<br/>uid: bf012aa908bd8d4464c9ab52cf088d3f |
>| GobLin | STIX Threat Actor | lastUpdated: 1611246675557<br/>handles: GobLin<br/>links: {"forums": [{"name": "mazafaka", "actorHandle": "GobLin", "uid": "fc221309746013ac554571fbd180e1c8"}], "forumTotalCount": 1, "instantMessageChannelTotalCount": 0, "forumPrivateMessageTotalCount": 0, "reportTotalCount": 0, "instantMessageTotalCount": 0, "instantMessageServerTotalCount": 0, "forumPostTotalCount": 10}<br/>activeFrom: 1099423620000<br/>activeUntil: 1099423620000<br/>uid: 09a6110f39478e39eda6c95138d7e723 |
>| SveSTevN | STIX Threat Actor | lastUpdated: 1611252975381<br/>handles: SveSTevN<br/>links: {"forums": [{"name": "mazafaka", "actorHandle": "SveSTevN", "uid": "fc221309746013ac554571fbd180e1c8"}], "forumTotalCount": 1, "instantMessageChannelTotalCount": 0, "forumPrivateMessageTotalCount": 0, "reportTotalCount": 0, "instantMessageTotalCount": 0, "instantMessageServerTotalCount": 0, "forumPostTotalCount": 13}<br/>activeFrom: 1099443060000<br/>activeUntil: 1099443060000<br/>uid: debbb920e2f6a94f875c6384af99ec35 |
>| Thomas | STIX Threat Actor | lastUpdated: 1611253575408<br/>handles: Thomas<br/>links: {"forums": [{"name": "mazafaka", "actorHandle": "Thomas", "uid": "fc221309746013ac554571fbd180e1c8"}], "forumTotalCount": 1, "instantMessageChannelTotalCount": 0, "forumPrivateMessageTotalCount": 0, "reportTotalCount": 0, "instantMessageTotalCount": 0, "instantMessageServerTotalCount": 0, "forumPostTotalCount": 1}<br/>activeFrom: 1099781940000<br/>activeUntil: 1099781940000<br/>uid: 2b9b3d1530d0cb2364053cce822297eb |
>| Petrovich | STIX Threat Actor | lastUpdated: 1611252674936<br/>handles: Petrovich<br/>links: {"forums": [{"name": "mazafaka", "actorHandle": "Petrovich", "uid": "fc221309746013ac554571fbd180e1c8"}], "forumTotalCount": 1, "instantMessageChannelTotalCount": 0, "forumPrivateMessageTotalCount": 0, "reportTotalCount": 0, "instantMessageTotalCount": 0, "instantMessageServerTotalCount": 0, "forumPostTotalCount": 3}<br/>activeFrom: 1099939140000<br/>activeUntil: 1099939140000<br/>uid: db1aa88e2f0c2d120d3f0930a0a2e9ed |
>| PoFigisT | STIX Threat Actor | lastUpdated: 1611252675579<br/>handles: PoFigisT<br/>links: {"forums": [{"name": "mazafaka", "actorHandle": "PoFigisT", "uid": "fc221309746013ac554571fbd180e1c8"}], "forumTotalCount": 1, "instantMessageChannelTotalCount": 0, "forumPrivateMessageTotalCount": 0, "reportTotalCount": 0, "instantMessageTotalCount": 0, "instantMessageServerTotalCount": 0, "forumPostTotalCount": 17}<br/>activeFrom: 1100332920000<br/>activeUntil: 1100332920000<br/>uid: 9c16382ba5454e06919e087959046f12 |
