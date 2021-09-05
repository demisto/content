This is the NucleonCyber Feed  integration
This integration was integrated and tested with version 6.0.0 of NucleonCyberFeed
## Configure NucleonCyberFeed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for NucleonCyberFeed.
3. Click **Add instance** to create and configure a new integration instance.

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

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### nucleon-get-indicators
***
Gets indicators from the feed.


#### Base Command

`nucleon-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The indecator type (ip, url or hash). Default is ip. | Required | 
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
                    "value": "138.122.20.95"
                },
                "segment": "governments",
                "service": "NucleonCyberFeed",
                "sourceCountry": "BR",
                "targetCountry": "SG",
                "type": "IP",
                "value": "138.122.20.95"
            },
            {
                "automated": false,
                "botnet": false,
                "bruteForce": false,
                "cnc": false,
                "darknet": false,
                "fields": {
                    "nucleonsegment": "telecom",
                    "os": "Linux",
                    "osversion": "3.11 and newer",
                    "port": 0,
                    "tags": [
                        "nucleon_bruteForce",
                        "nucleon_bruteForce"
                    ],
                    "targetCountry": "CA",
                    "trafficlightprotocol": "GREEN"
                },
                "governments": false,
                "os": "Linux",
                "osVersion": "3.11 and newer",
                "port": 0,
                "proxy": false,
                "rawJSON": {
                    "automated": false,
                    "bot": false,
                    "botnet": false,
                    "bruteForce": false,
                    "cnc": false,
                    "darknet": false,
                    "exp": "1629991512",
                    "governments": false,
                    "os": "Linux",
                    "osVersion": "3.11 and newer",
                    "port": 0,
                    "proxy": false,
                    "segment": "telecom",
                    "sourceCountry": "MD",
                    "targetCountry": "CA",
                    "type": "IP",
                    "value": "5.182.39.75"
                },
                "segment": "telecom",
                "service": "NucleonCyberFeed",
                "sourceCountry": "MD",
                "targetCountry": "CA",
                "type": "IP",
                "value": "5.182.39.75"
            },
            {
                "automated": false,
                "botnet": false,
                "bruteForce": true,
                "cnc": false,
                "darknet": false,
                "fields": {
                    "nucleonsegment": "governments",
                    "os": "Linux",
                    "osversion": "2.2.x-3.x",
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
                "osVersion": "2.2.x-3.x",
                "port": 0,
                "proxy": false,
                "rawJSON": {
                    "automated": false,
                    "bot": false,
                    "botnet": false,
                    "bruteForce": true,
                    "cnc": false,
                    "darknet": false,
                    "exp": "1629991517",
                    "governments": false,
                    "os": "Linux",
                    "osVersion": "2.2.x-3.x",
                    "port": 0,
                    "proxy": false,
                    "segment": "governments",
                    "sourceCountry": "VE",
                    "targetCountry": "SG",
                    "type": "IP",
                    "value": "191.97.19.138"
                },
                "segment": "governments",
                "service": "NucleonCyberFeed",
                "sourceCountry": "VE",
                "targetCountry": "SG",
                "type": "IP",
                "value": "191.97.19.138"
            },
            {
                "automated": false,
                "botnet": false,
                "bruteForce": false,
                "cnc": false,
                "darknet": false,
                "fields": {
                    "nucleonsegment": "telecom",
                    "os": "Linux",
                    "osversion": "3.11 and newer",
                    "port": 0,
                    "tags": [
                        "nucleon_bruteForce",
                        "nucleon_bruteForce"
                    ],
                    "targetCountry": "CA",
                    "trafficlightprotocol": "GREEN"
                },
                "governments": false,
                "os": "Linux",
                "osVersion": "3.11 and newer",
                "port": 0,
                "proxy": false,
                "rawJSON": {
                    "automated": false,
                    "bot": false,
                    "botnet": false,
                    "bruteForce": false,
                    "cnc": false,
                    "darknet": false,
                    "exp": "1629991521",
                    "governments": false,
                    "os": "Linux",
                    "osVersion": "3.11 and newer",
                    "port": 0,
                    "proxy": false,
                    "segment": "telecom",
                    "sourceCountry": "LT",
                    "targetCountry": "CA",
                    "type": "IP",
                    "value": "141.98.10.125"
                },
                "segment": "telecom",
                "service": "NucleonCyberFeed",
                "sourceCountry": "LT",
                "targetCountry": "CA",
                "type": "IP",
                "value": "141.98.10.125"
            },
            {
                "automated": false,
                "botnet": false,
                "bruteForce": false,
                "cnc": false,
                "darknet": false,
                "fields": {
                    "nucleonsegment": "fintech",
                    "os": "Linux",
                    "osversion": "3.11 and newer",
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
                "osVersion": "3.11 and newer",
                "port": 0,
                "proxy": false,
                "rawJSON": {
                    "automated": false,
                    "bot": false,
                    "botnet": false,
                    "bruteForce": false,
                    "cnc": false,
                    "darknet": false,
                    "exp": "1629991524",
                    "governments": false,
                    "os": "Linux",
                    "osVersion": "3.11 and newer",
                    "port": 0,
                    "proxy": false,
                    "segment": "fintech",
                    "sourceCountry": "CN",
                    "targetCountry": "SG",
                    "type": "IP",
                    "value": "121.4.253.21"
                },
                "segment": "fintech",
                "service": "NucleonCyberFeed",
                "sourceCountry": "CN",
                "targetCountry": "SG",
                "type": "IP",
                "value": "121.4.253.21"
            },
            {
                "automated": false,
                "botnet": false,
                "bruteForce": false,
                "cnc": false,
                "darknet": false,
                "fields": {
                    "nucleonsegment": null,
                    "os": "Linux",
                    "osversion": "3.1-3.10",
                    "port": 0,
                    "tags": [
                        "nucleon_bruteForce",
                        "nucleon_bruteForce"
                    ],
                    "targetCountry": "DE",
                    "trafficlightprotocol": "GREEN"
                },
                "governments": false,
                "os": "Linux",
                "osVersion": "3.1-3.10",
                "port": 0,
                "proxy": false,
                "rawJSON": {
                    "automated": false,
                    "bot": false,
                    "botnet": false,
                    "bruteForce": false,
                    "cnc": false,
                    "darknet": false,
                    "exp": "1629991525",
                    "governments": false,
                    "os": "Linux",
                    "osVersion": "3.1-3.10",
                    "port": 0,
                    "proxy": false,
                    "segment": null,
                    "sourceCountry": "BR",
                    "targetCountry": "DE",
                    "type": "IP",
                    "value": "187.109.13.13"
                },
                "segment": null,
                "service": "NucleonCyberFeed",
                "sourceCountry": "BR",
                "targetCountry": "DE",
                "type": "IP",
                "value": "187.109.13.13"
            },
            {
                "automated": false,
                "botnet": false,
                "bruteForce": true,
                "cnc": false,
                "darknet": false,
                "fields": {
                    "nucleonsegment": "governments",
                    "os": "Linux",
                    "osversion": "2.2.x-3.x",
                    "port": 0,
                    "tags": [
                        "nucleon_bruteForce",
                        "nucleon_bruteForce"
                    ],
                    "targetCountry": "KR",
                    "trafficlightprotocol": "GREEN"
                },
                "governments": false,
                "os": "Linux",
                "osVersion": "2.2.x-3.x",
                "port": 0,
                "proxy": false,
                "rawJSON": {
                    "automated": false,
                    "bot": false,
                    "botnet": false,
                    "bruteForce": true,
                    "cnc": false,
                    "darknet": false,
                    "exp": "1629991525",
                    "governments": false,
                    "os": "Linux",
                    "osVersion": "2.2.x-3.x",
                    "port": 0,
                    "proxy": false,
                    "segment": "governments",
                    "sourceCountry": "US",
                    "targetCountry": "KR",
                    "type": "IP",
                    "value": "40.86.90.3"
                },
                "segment": "governments",
                "service": "NucleonCyberFeed",
                "sourceCountry": "US",
                "targetCountry": "KR",
                "type": "IP",
                "value": "40.86.90.3"
            },
            {
                "automated": false,
                "botnet": false,
                "bruteForce": false,
                "cnc": false,
                "darknet": false,
                "fields": {
                    "nucleonsegment": "telecom",
                    "os": "Linux",
                    "osversion": "2.2.x-3.x",
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
                "osVersion": "2.2.x-3.x",
                "port": 0,
                "proxy": false,
                "rawJSON": {
                    "automated": false,
                    "bot": false,
                    "botnet": false,
                    "bruteForce": false,
                    "cnc": false,
                    "darknet": false,
                    "exp": "1629991530",
                    "governments": false,
                    "os": "Linux",
                    "osVersion": "2.2.x-3.x",
                    "port": 0,
                    "proxy": false,
                    "segment": "telecom",
                    "sourceCountry": "TW",
                    "targetCountry": "SG",
                    "type": "IP",
                    "value": "34.81.40.119"
                },
                "segment": "telecom",
                "service": "NucleonCyberFeed",
                "sourceCountry": "TW",
                "targetCountry": "SG",
                "type": "IP",
                "value": "34.81.40.119"
            },
            {
                "automated": false,
                "botnet": false,
                "bruteForce": false,
                "cnc": false,
                "darknet": false,
                "fields": {
                    "nucleonsegment": "telecom",
                    "os": "Linux",
                    "osversion": "2.2.x-3.x",
                    "port": 0,
                    "tags": [
                        "nucleon_bruteForce",
                        "nucleon_bruteForce"
                    ],
                    "targetCountry": "CA",
                    "trafficlightprotocol": "GREEN"
                },
                "governments": false,
                "os": "Linux",
                "osVersion": "2.2.x-3.x",
                "port": 0,
                "proxy": false,
                "rawJSON": {
                    "automated": false,
                    "bot": false,
                    "botnet": false,
                    "bruteForce": false,
                    "cnc": false,
                    "darknet": false,
                    "exp": "1629991531",
                    "governments": false,
                    "os": "Linux",
                    "osVersion": "2.2.x-3.x",
                    "port": 0,
                    "proxy": false,
                    "segment": "telecom",
                    "sourceCountry": "US",
                    "targetCountry": "CA",
                    "type": "IP",
                    "value": "199.195.253.187"
                },
                "segment": "telecom",
                "service": "NucleonCyberFeed",
                "sourceCountry": "US",
                "targetCountry": "CA",
                "type": "IP",
                "value": "199.195.253.187"
            },
            {
                "automated": false,
                "botnet": false,
                "bruteForce": false,
                "cnc": false,
                "darknet": false,
                "fields": {
                    "nucleonsegment": null,
                    "os": "Linux",
                    "osversion": "2.2.x-3.x",
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
                "osVersion": "2.2.x-3.x",
                "port": 0,
                "proxy": false,
                "rawJSON": {
                    "automated": false,
                    "bot": false,
                    "botnet": false,
                    "bruteForce": false,
                    "cnc": false,
                    "darknet": false,
                    "exp": "1629991532",
                    "governments": false,
                    "os": "Linux",
                    "osVersion": "2.2.x-3.x",
                    "port": 0,
                    "proxy": false,
                    "segment": null,
                    "sourceCountry": "US",
                    "targetCountry": "SG",
                    "type": "IP",
                    "value": "192.35.168.160"
                },
                "segment": null,
                "service": "NucleonCyberFeed",
                "sourceCountry": "US",
                "targetCountry": "SG",
                "type": "IP",
                "value": "192.35.168.160"
            }
        ]
    }
}
```

#### Human Readable Output

>### IP indicators from NucleonCyberFeed: 
>|Value|Type|
>|---|---|
>| 138.122.20.95 | IP |
>| 5.182.39.75 | IP |
>| 191.97.19.138 | IP |
>| 141.98.10.125 | IP |
>| 121.4.253.21 | IP |
>| 187.109.13.13 | IP |
>| 40.86.90.3 | IP |
>| 34.81.40.119 | IP |
>| 199.195.253.187 | IP |
>| 192.35.168.160 | IP |

