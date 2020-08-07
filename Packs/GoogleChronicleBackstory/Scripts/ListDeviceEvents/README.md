List all of the events discovered within your enterprise on a particular device within 2 hours earlier than the current time.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | enhancement |
| Demisto Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* gcb-list-events

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| asset_identifier | Host Name, IP Address or MAC Address of the asset. |

## Outputs
---
There are no outputs for this script.

## Script Example
```!ListDeviceEvents asset_identifier="ray-xxx-laptop"

##### Context Example
```
{
    "GoogleChronicleBackstory.Events": [
        {
            "principal": {
                "ip": [
                    "10.0.XX.XX"
                ], 
                "mac": [
                    "88:a6:XX:XX:XX:XX"
                ], 
                "hostname": "ray-xxx-laptop"
            }, 
            "target": {
                "ip": [
                    "8.8.8.8"
                ]
            }, 
            "network": {
                "applicationProtocol": "DNS", 
                "dns": {
                    "questions": [
                        {
                            "type": 1, 
                            "name": "is5-ssl.mzstatic.com"
                        }
                    ], 
                    "answers": [
                        {
                            "type": 1, 
                            "data": "104.118.212.43", 
                            "name": "is5-ssl.mzstatic.com", 
                            "ttl": 11111
                        }
                    ], 
                    "response": true
                }
            }, 
            
            "collectedTimestamp": "2020-01-02T00:00:00Z", 
            "productName": "ExtraHop", 
            "eventTimestamp": "2020-01-01T23:59:38Z", 
            "eventType": "NETWORK_DNS"
        
        }
    ]
}
```

##### Human Readable Output
>### Event(s) Details
>|Event Timestamp|Event Type|Principal Asset Identifier|Target Asset Identifier|Queried Domain|
>|---|---|---|---|---|
>| 2020-01-01T23:59:38Z | NETWORK_DNS | ray-xxx-laptop | 8.8.8.8 | ninthdecimal.com |
>
>View events in Chronicle
>
>Maximum number of events specified in page_size has been returned. There might still be more events in your Chronicle account. >To fetch the next set of events, execute the command with the start time as 2020-01-01T23:59:38Z
