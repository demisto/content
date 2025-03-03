This is the NucleonCyber Feed  integration
This integration was integrated and tested with version 6.0.0 of NucleonCyberFeed
## Configure NucleonCyberFeed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch indicators |  | False |
| Server's URL | Should be feed of type .txt. For using other types of feed, modify the parsing in the python file. | True |
| User Name | The given username to use for NucleonCyber API connection | True |
| Password | The given password to use for NucleonCyber API connection | True |
| Usrn | The given usrn to use for NucleonCyber API connection | True |
| ClientID | The given clientID to use for NucleonCyber API connection | True |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
|  |  | False |
|  |  | False |
| Tags | Supports CSV values. | False |
| Incremental feed | Incremental feeds pull only new or modified indicators that have been sent from the integration. The determination if the indicator is new or modified happens on the 3rd-party vendor's side, so only indicators that are new or modified are sent to Cortex XSOAR. Therefore, all indicators coming from these feeds are labeled new or modified. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nucleon-get-indicators
***
Gets indicators from the feed.


#### Base Command

`nucleon-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The indicator type (ip, url or hash). Default is ip. | Required | 
| limit | The maximum number of results to return. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NucleonCyber.Indicators.value | String | IP/HASH/URL. | 
| NucleonCyber.Indicators.exp | String | Indicators exp. | 


#### Command Example
```!nucleon-get-indicators```

#### Context Example
```json
{
    "NucleonCyber": {
        "Indicators": [
            {
                "automated": false,
                "botnet": false,
                "bruteForce": false,
                "cnc": false,
                "darknet": false,
                "fields": {
                    "nucleonsegment": "governments",
                    "os": "Linux",
                    "osversion": "3.x",
                    "port": 0,
                    "tags": [
                        "nucleon_bruteForce",
                        "nucleon_bruteForce"
                    ],
                    "targetCountry": "SG",
                    "trafficlightprotocol": "GREEN"
                },
                "governments": false,
                "os": "Linux",
                "osVersion": "3.x",
                "port": 0,
                "proxy": false,
                "rawJSON": {
                    "automated": false,
                    "bot": false,
                    "botnet": false,
                    "bruteForce": false,
                    "cnc": false,
                    "darknet": false,
                    "exp": "1629991508",
                    "governments": false,
                    "os": "Linux",
                    "osVersion": "3.x",
                    "port": 0,
                    "proxy": false,
                    "segment": "governments",
                    "sourceCountry": "BR",
                    "targetCountry": "SG",
                    "type": "IP",
                    "value": "4.4.4.4"
                },
                "segment": "governments",
                "service": "NucleonCyberFeed",
                "sourceCountry": "BR",
                "targetCountry": "SG",
                "type": "IP",
                "value": "4.4.4.4"
            }
        ]
    }
}
```

#### Human Readable Output

>### IP indicators from NucleonCyberFeed: 
>|Value|Type|
>|---|---|
>| 4.4.4.4 | IP |