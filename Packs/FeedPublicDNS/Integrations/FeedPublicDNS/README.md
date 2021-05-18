A feed of known benign IPs of public DNS servers.
## Configure Public DNS Feed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Public DNS Feed.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Public DNS feed URL | True |
    | feed | Fetch indicators | False |
    | feedReputation | Indicator Reputation | False |
    | feedReliability | Source Reliability | True |
    | feedExpirationPolicy |  | False |
    | feedFetchInterval | Feed Fetch Interval | False |
    | feedExpirationInterval |  | False |
    | feedTags | Tags | False |
    | feedBypassExclusionList | Bypass exclusion list | False |
    | tlp_color | Traffic Light Protocol Color | False |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### public-dns-get-indicators
***
Gets indicators from the feed.


#### Base Command

`public-dns-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. The default value is 10. Default is 10. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!public-dns-get-indicators limit=2```

#### Context Example
```json
{
    "Indicator": [
        {
            "rawJSON": {
                "type": "IPv6",
                "value": "2607:5300:203:1797::53"
            },
            "score": 0,
            "type": "IPv6",
            "value": "2607:5300:203:1797::53"
        },
        {
            "rawJSON": {
                "type": "Ip",
                "value": "199.255.137.34"
            },
            "score": 0,
            "type": "Ip",
            "value": "199.255.137.34"
        }
    ]
}
```

#### Human Readable Output

>### Public DNS Feed:
>|value|type|
>|---|---|
>| 2607:5300:203:1797::53 | IPv6 |
>| 199.255.137.34 | Ip |

