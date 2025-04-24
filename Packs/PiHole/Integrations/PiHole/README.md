Pi-hole is a network-level advertisement and Internet tracker blocking application which acts as a DNS sinkhole and optionally a DHCP server, intended for use on a private network.
This integration was integrated and tested with version FTL5.2 of PiHole
## Configure PiHole in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL | True |
| token | Auth Token | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pihole-get-version
***
Returns the version of the API


#### Base Command

`pihole-get-version`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.Version.version | string | Version info | 


#### Command Example
```!pihole-get-version```

#### Context Example
```
{
    "PiHole": {
        "Version": {
            "version": 3
        }
    }
}
```

#### Human Readable Output

>### Results
>|version|
>|---|
>| 3 |


### pihole-get-type
***
Returns the backend used by the API (either PHP or FTL)


#### Base Command

`pihole-get-type`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.Type.type | string | Type information | 


#### Command Example
```!pihole-get-type```

#### Context Example
```
{
    "PiHole": {
        "Type": {
            "type": "FTL"
        }
    }
}
```

#### Human Readable Output

>### Results
>|type|
>|---|
>| FTL |


### pihole-get-summaryraw
***
Gives statistics in raw format (no number formatting applied)


#### Base Command

`pihole-get-summaryraw`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.SummaryRaw | string | Summary no formatting | 


#### Command Example
```!pihole-get-summaryraw```

#### Context Example
```
{
    "PiHole": {
        "SummaryRaw": {
            "ads_blocked_today": 457,
            "ads_percentage_today": 2.387296,
            "clients_ever_seen": 15,
            "dns_queries_all_types": 19143,
            "dns_queries_today": 19143,
            "domains_being_blocked": 85512,
            "gravity_last_updated": {
                "absolute": 1597037232,
                "file_exists": true,
                "relative": {
                    "days": 2,
                    "hours": 5,
                    "minutes": 41
                }
            },
            "privacy_level": 0,
            "queries_cached": 9086,
            "queries_forwarded": 9595,
            "reply_CNAME": 5811,
            "reply_IP": 8696,
            "reply_NODATA": 1664,
            "reply_NXDOMAIN": 1622,
            "status": "disabled",
            "unique_clients": 15,
            "unique_domains": 1551
        }
    }
}
```

#### Human Readable Output

>### Results
>|ads_blocked_today|ads_percentage_today|clients_ever_seen|dns_queries_all_types|dns_queries_today|domains_being_blocked|gravity_last_updated|privacy_level|queries_cached|queries_forwarded|reply_CNAME|reply_IP|reply_NODATA|reply_NXDOMAIN|status|unique_clients|unique_domains|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 457 | 2.387296 | 15 | 19143 | 19143 | 85512 | file_exists: true<br/>absolute: 1597037232<br/>relative: {"days": 2, "hours": 5, "minutes": 41} | 0 | 9086 | 9595 | 5811 | 8696 | 1664 | 1622 | disabled | 15 | 1551 |


### pihole-get-overtimedata10mins
***
Data needed for generating the domains/ads over time graph on the Pi-hole web dashboard


#### Base Command

`pihole-get-overtimedata10mins`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.OverTimeData10mins | string | Data over last 10mins | 


#### Command Example
```!pihole-get-overtimedata10mins```

#### Context Example
```
{
    "PiHole": {
        "OverTimeData10mins": {
            "ads_over_time": {
                "1597147500": 2,
                "1597148100": 1,
                "1597148700": 6,
                ...,
                "1597230300": 0
            },
            "domains_over_time": {
                "1597147500": 81,
                "1597148100": 96,
                "1597148700": 85,
                ...,
                "1597230300": 423
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|ads_over_time|domains_over_time|
>|---|---|
>| 1597147500: 2<br/>1597148100: 1<br/>1597148700: 6<br/>1597230300: 0 | 1597147500: 81<br/>1597148100: 96<br/>1597148700: 85<br/>1597230300: 423 |


### pihole-get-topitems
***
Data needed for generating the Top Domain and Top Advertisers Lists


#### Base Command

`pihole-get-topitems`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | how many entries | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.TopItems | string | Top Items | 


#### Command Example
```!pihole-get-topitems```

#### Context Example
```
{
    "PiHole": {
        "TopItems": {
            "top_ads": {
                "api.segment.io": 22,
                "app-measurement.com": 180,
                "cf.iadsdk.apple.com": 9,
                "dhg-logging.us-east-1.elasticbeanstalk.com": 9,
                "iadsdk.apple.com": 64,
                "logging.dhg.myharmony.com": 9,
                "notify.bugsnag.com": 12,
                "pingma.qq.com": 50,
                "static.hotjar.com": 7,
                "www.google-analytics.com": 7
            },
            "top_queries": {
                "agent-gateway-api-prod-eu.traps.paloaltonetworks.com": 1355,
                "ch-xyz.traps.paloaltonetworks.com": 815,
                "dc-xyz.traps.paloaltonetworks.com": 338,
                "gateway.icloud.com": 561,
                "gsp-ssl.ls-apple.com.akadns.net": 387,
                "gsp-ssl.ls.apple.com": 349,
                "xyz": 903,
                "www.google.com": 3153,
                "www.apple.com": 1144
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|top_ads|top_queries|
>|---|---|
>| app-measurement.com: 180<br/>iadsdk.apple.com: 64<br/>pingma.qq.com: 50<br/>api.segment.io: 22<br/>notify.bugsnag.com: 12<br/>logging.dhg.myharmony.com: 9<br/>dhg-logging.us-east-1.elasticbeanstalk.com: 9<br/>cf.iadsdk.apple.com: 9<br/>www.google-analytics.com: 7<br/>static.hotjar.com: 7 | www.google.com: 3153<br/>agent-gateway-api-prod-eu.traps.paloaltonetworks.com: 1355<br/>xyz: 903<br/>ch-xyz.traps.paloaltonetworks.com: 815<br/>gateway.icloud.com: 561<br/>gsp-ssl.ls-apple.com.akadns.net: 387<br/>gsp-ssl.ls.apple.com: 349<br/>dc-xyz.traps.paloaltonetworks.com: 338 |


### pihole-get-topclients
***
Data needed for generating the Top Clients list


#### Base Command

`pihole-get-topclients`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | how many entries | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.TopClients | string | Top Clients | 


#### Command Example
```!pihole-get-topclients```

#### Context Example
```
{
    "PiHole": {
        "TopClients": {
            "top_sources": {
                "192.168.0.1": 497,
                "192.168.0.2": 5964,
                "192.168.0.3": 338,
                "mymachine.local|192.168.0.20": 1627,
                "localhost.localdomain|127.0.0.1": 336
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|top_sources|
>|---|
>| 192.168.0.2: 5964<br/>mymachine.local\|192.168.0.20: 1627<br/>192.168.0.1: 497<br/>192.168.0.3: 338<br/>localhost.localdomain\|127.0.0.1: 336 |


### pihole-get-forward-destinations
***
Shows number of queries that have been forwarded and the target


#### Base Command

`pihole-get-forward-destinations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.ForwardDestinations | string | Fowarding destinations | 


#### Command Example
```!pihole-get-forward-destinations```

#### Context Example
```
{
    "PiHole": {
        "ForwardDestinations": {
            "forward_destinations": {
                "1.1.1.2": 24.77,
                "1.1.1.3": 25.42,
                "blocklist|blocklist": 2.39,
                "cache|cache": 47.48
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|forward_destinations|
>|---|
>| blocklist\|blocklist: 2.39<br/>cache\|cache: 47.48<br/>1.1.1.3: 25.42<br/>1.0.0.3: 24.77 |


### pihole-get-query-types
***
Shows number of queries that the Pi-hole’s DNS server has processed


#### Base Command

`pihole-get-query-types`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.QueryTypes | string | Query types | 


#### Command Example
```!pihole-get-query-types```

#### Context Example
```
{
    "PiHole": {
        "QueryTypes": {
            "querytypes": {
                "A (IPv4)": 75.52,
                "AAAA (IPv6)": 15.08,
                "ANY": 0,
                "DNSKEY": 0,
                "DS": 0,
                "MX": 0,
                "NAPTR": 0,
                "OTHER": 0,
                "PTR": 3.13,
                "RRSIG": 0,
                "SOA": 5.19,
                "SRV": 0.6,
                "TXT": 0.48
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|querytypes|
>|---|
>| A (IPv4): 75.52<br/>AAAA (IPv6): 15.08<br/>ANY: 0<br/>SRV: 0.6<br/>SOA: 5.19<br/>PTR: 3.13<br/>TXT: 0.48<br/>NAPTR: 0<br/>MX: 0<br/>DS: 0<br/>RRSIG: 0<br/>DNSKEY: 0<br/>OTHER: 0 |


### pihole-get-all-queries
***
Get DNS queries data


#### Base Command

`pihole-get-all-queries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.AllQueries | string | All Queries \(a lot of data\) | 


#### Command Example
```!pihole-get-all-queries```

#### Human Readable Output
This command will return all queries. Its a big list in a file.


### pihole-status
***
Show status of pihole action (enabled - disabled)


#### Base Command

`pihole-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.Status | string | Status | 


#### Command Example
```!pihole-status```

#### Context Example
```
{
    "PiHole": {
        "Status": {
            "status": "disabled"
        }
    }
}
```

#### Human Readable Output

>### Results
>|status|
>|---|
>| disabled |


### pihole-enable
***
Enable Pi-hole ad blocking


#### Base Command

`pihole-enable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.Enable | string | Enabled blocking | 


#### Command Example
```!pihole-enable```

#### Context Example
```
{
    "PiHole": {
        "Enable": {
            "status": "enabled"
        }
    }
}
```

#### Human Readable Output

>### Results
>|status|
>|---|
>| enabled |


### pihole-disable
***
used to disable pihole for certain amount of time


#### Base Command

`pihole-disable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time | Time in seconds for blocking to be disabled | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.Disable | string | Disabled | 


#### Command Example
```!pihole-disable```

#### Context Example
```
{
    "PiHole": {
        "Disable": {
            "status": "disabled"
        }
    }
}
```

#### Human Readable Output

>### Results
>|status|
>|---|
>| disabled |


### pihole-get-versions
***
Show versions of all components


#### Base Command

`pihole-get-versions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.Versions | string | Version info | 


#### Command Example
```!pihole-get-versions```

#### Context Example
```
{
    "PiHole": {
        "Versions": {
            "FTL_branch": "master",
            "FTL_current": "v5.2",
            "FTL_latest": "v5.2",
            "FTL_update": false,
            "core_branch": "master",
            "core_current": "v5.1.2",
            "core_latest": "v5.1.2",
            "core_update": false,
            "web_branch": "master",
            "web_current": "v5.1.1",
            "web_latest": "v5.1.1",
            "web_update": false
        }
    }
}
```

#### Human Readable Output

>### Results
>|FTL_branch|FTL_current|FTL_latest|FTL_update|core_branch|core_current|core_latest|core_update|web_branch|web_current|web_latest|web_update|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| master | v5.2 | v5.2 | false | master | v5.1.2 | v5.1.2 | false | master | v5.1.1 | v5.1.1 | false |


### pihole-get-topclientsblocked
***
Shows the top clients being blocked


#### Base Command

`pihole-get-topclientsblocked`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.TopClientsBlocked | string | Top blocked clients | 


#### Command Example
```!pihole-get-topclientsblocked```

#### Context Example
```
{
    "PiHole": {
        "TopClientsBlocked": null
    }
}
```

#### Human Readable Output

>### Results
>**No entries.**


### pihole-get-cache-info
***
Show cache info


#### Base Command

`pihole-get-cache-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.CacheInfo | string | Cache info | 


#### Command Example
```!pihole-get-cache-info```

#### Context Example
```
{
    "PiHole": {
        "CacheInfo": {
            "cacheinfo": {
                "cache-inserted": 99,
                "cache-live-freed": 0,
                "cache-size": 10000
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|cacheinfo|
>|---|
>| cache-size: 10000<br/>cache-live-freed: 0<br/>cache-inserted: 99 |


### pihole-get-recent-blocked
***
Show most recent blocked domain


#### Base Command

`pihole-get-recent-blocked`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.RecentBlocked | string | Recently blocked | 


#### Command Example
```!pihole-get-recent-blocked```

#### Context Example
```
{
    "PiHole": {
        "RecentBlocked": {
            "Data": "abc.xyz.com"
        }
    }
}
```

#### Human Readable Output

>### Results
>|Data|
>|---|
>| abc.xyz.com |


### pihole-get-overTimeDataQueryTypes
***
Get data over time per query types


#### Base Command

`pihole-get-overTimeDataQueryTypes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.OverTimeDataQueryTypes | string | Over time query types | 


#### Command Example
```!pihole-get-overTimeDataQueryTypes```

#### Context Example
```
{
    "PiHole": {
        "OverTimeDataQueryTypes": {
            "over_time": {
                "1597147500": [
                    87.34,
                    12.66
                ],
                "1597148100": [
                    91.67,
                    8.33
                ],
                "1597148700": [
                    90.12,
                    9.88
                ],
                "1597230300": [
                    63.33,
                    36.67
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|over_time|
>|---|
>| 1597147500: 87.34,<br/>12.66<br/>1597148100: 91.67,<br/>8.33<br/>1597148700: 90.12,<br/>9.88<br/>1597230300: 63.33,<br/>36.67 |


### pihole-get-client-names
***
Get client names


#### Base Command

`pihole-get-client-names`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.ClientNames | string | Client names | 


#### Command Example
```!pihole-get-client-names```

#### Context Example
```
{
    "PiHole": {
        "ClientNames": {
            "clients": [
                {
                    "ip": "192.168.0.1",
                    "name": "mymachine1.local"
                },
                {
                    "ip": "192.168.0.2",
                    "name": "mymachine2.local"
                },
                {
                    "ip": "192.168.0.3",
                    "name": "mymachine3.local"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|clients|
>|---|
>| {'name': 'mymachine1.local', 'ip': '192.168.0.1'},<br/>{'name': 'mymachine2.local', 'ip': '192.168.0.2'},<br/>{'name': 'mymachine3.local', 'ip': '192.168.0.3'} |


### pihole-get-over-time-data-clients
***
Get over time data clients


#### Base Command

`pihole-get-over-time-data-clients`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.OverTimeDataClients | string | Over time client data | 


#### Command Example
```!pihole-get-over-time-data-clients```

#### Context Example
```
{
    "PiHole": {
        "OverTimeDataClients": {
            "over_time": {
                "1597147500": [
                    0,
                    24,
                    41,
                    1,
                    2,
                    10,
                    2,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0
                ],
                "1597148100": [
                    0,
                    50,
                    33,
                    0,
                    3,
                    8,
                    1,
                    1,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0
                ],
                "1597148700": [
                    0,
                    30,
                    5,
                    1,
                    3,
                    21,
                    0,
                    0,
                    25,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0
                ],
                "1597230300": [
                    367,
                    38,
                    0,
                    16,
                    2,
                    0,
                    2,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|over_time|
>|---|
>| 1597147500: 0,<br/>24,<br/>41,<br/>1,<br/>2,<br/>10,<br/>2,<br/>1,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0<br/>1597148100: 0,<br/>50,<br/>33,<br/>0,<br/>3,<br/>8,<br/>1,<br/>1,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0<br/>1597148700: 0,<br/>30,<br/>5,<br/>1,<br/>3,<br/>21,<br/>0,<br/>0,<br/>25,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0<br/>1597230300: 367,<br/>38,<br/>0,<br/>16,<br/>2,<br/>0,<br/>2,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0,<br/>0 |


### pihole-list-management
***
Manage lists. Add or remove items from lists


#### Base Command

`pihole-list-management`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to be added or removed | Optional | 
| action | add or sub | Optional | 
| list | which list to interact with | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.List | string | Lists | 


#### Command Example
```!pihole-list-management list=white action=add domain=paloaltonetworks.com```

#### Context Example
```
{
    "PiHole": {
        "List": {
            "message": "Added paloaltonetworks.com",
            "success": true
        }
    }
}
```

#### Human Readable Output

>### Results
>|message|success|
>|---|---|
>| Added paloaltonetworks.com | true |


### pihole-get-list
***
Get all available lists from Pihole


#### Base Command

`pihole-get-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list | which list to get | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PiHole.Lists | string | get a list data | 


#### Command Example
```!pihole-get-list list=white```

#### Context Example
```
{
    "PiHole": {
        "Lists": {
            "data": [
                {
                    "comment": null,
                    "date_added": 1593758659,
                    "date_modified": 1593758659,
                    "domain": "www.googleadservices.com",
                    "enabled": 1,
                    "groups": [
                        0
                    ],
                    "id": 2,
                    "type": 0
                },
                {
                    "comment": null,
                    "date_added": 1593758671,
                    "date_modified": 1593758671,
                    "domain": "www.googletagmanager.com",
                    "enabled": 1,
                    "groups": [
                        0
                    ],
                    "id": 3,
                    "type": 0
                },
                {
                    "comment": null,
                    "date_added": 1594876318,
                    "date_modified": 1594876318,
                    "domain": "google.com",
                    "enabled": 1,
                    "groups": [
                        0
                    ],
                    "id": 8,
                    "type": 0
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|data|
>|---|
>| {'id': 2, 'type': 0, 'domain': 'www.googleadservices.com', 'enabled': 1, 'date_added': 1593758659, 'date_modified': 1593758659, 'comment': None, 'groups': [0]},<br/>{'id': 3, 'type': 0, 'domain': 'www.googletagmanager.com', 'enabled': 1, 'date_added': 1593758671, 'date_modified': 1593758671, 'comment': None, 'groups': [0]},<br/>{'id': 8, 'type': 0, 'domain': 'google.com', 'enabled': 1, 'date_added': 1594876318, 'date_modified': 1594876318, 'comment': None, 'groups': [0]} |
