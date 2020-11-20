Use FeedExpanse to retrieve the list of discovered IPs/Domains/Certificates from Expander
This integration was integrated and tested with version xx of FeedExpanse
## Configure FeedExpanse on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for FeedExpanse.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Your server URL | True |
| apikey | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| feed | Fetch indicators | False |
| maxIndicators | The maximum number of indicators to fetch. | False |
| minLastObserved | Retrieve indicators observed in the last specified number of days | False |
| feedExpirationPolicy |  | False |
| feedExpirationInterval |  | False |
| feedFetchInterval | Feed Fetch Interval | False |
| feedBypassExclusionList | Bypass exclusion list | False |
| feedReliability | Source Reliability | True |
| feedReputation | Indicator Reputation | False |
| feedTags | Tags | False |
| tlp_color | Traffic Light Protocol Color | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### feedexpanse-get-indicators
***
Retrieve discovered IPs/Domains/Certificates as indicators


#### Base Command

`feedexpanse-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max_indicators | The maximum number of results to return per type | Optional | 
| ip | Retrieve discovered IPs | Optional | 
| domain | Retrieve discovered Domains | Optional | 
| certificate | Retrieve discovered certificates | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Expanse.Indicator | Unknown | Expanse Discovered Assets | 


#### Command Example
```!feedexpanse-get-indicators max_indicators=1 certificate=yes ip=yes domain=yes```

#### Context Example
```json
{
    "Expanse": {
        "Indicator": [
            {
                "fields": {
                    "expanseassetype": "CERTIFICATE",
                    "expansebusinessunits": [
                        "DevRel"
                    ],
                    "expansecommonname": "test.pan.dev",
                    "expansedomain": null,
                    "expanselastobserved": "2020-10-19T00:20:07Z",
                    "expanseprovidername": "Google",
                    "expansetenantname": "Palo Alto Networks",
                    "expansetype": "CERTIFICATE_SIGHTING",
                    "lastseenbysource": "2020-10-19T00:20:07Z"
                },
                "rawJSON": {...},
                "score": 0,
                "type": "IP",
                "value": "1.2.3.4"
            },
            {
                "fields": {
                    "expansebusinessunits": [
                        "DevRel"
                    ],
                    "expansecertificateadvertisementstatus": [
                        "HAS_CERTIFICATE_ADVERTISEMENT"
                    ],
                    "expansecommonname": "test.pan.dev",
                    "expansedateadded": "2020-10-19T04:11:26.698Z",
                    "expansefirstobserved": "2020-10-17T00:00:00Z",
                    "expanseissuerdn": "CN=FakeCA",
                    "expanselastobserved": "2020-10-19T00:00:00Z",
                    "expansepemmd5hash": "B4YDxJd6wEIcPVsOE7iRdA==",
                    "expanseproperties": "WILDCARD\nDOMAIN_CONTROL_VALIDATED",
                    "expanseprovidername": null,
                    "expansesans": "test.pan.dev\n*.pan.dev",
                    "expanseserialnumber": "1",
                    "expanseservicestatus": [
                        "HAS_ACTIVE_SERVICE",
                        "NO_ACTIVE_CLOUD_SERVICE",
                        "HAS_ACTIVE_ON_PREM_SERVICE"
                    ],
                    "expansesubjectdn": "CN=test.pan.dev",
                    "expansetags": [],
                    "expansetenantname": "Palo Alto Networks",
                    "expansevalidnotafter": "2021-10-16T18:25:06Z",
                    "expansevalidnotbefore": "2020-10-16T18:25:06Z",
                    "firstseenbysource": "2020-10-17T00:00:00Z",
                    "lastseenbysource": "2020-10-19T00:00:00Z"
                },
                "rawJSON": {...},
                "score": 0,
                "type": "ExpanseCertificate",
                "value": "B4YDxJd6wEIcPVsOE7iRdA=="
            },
            {
                "fields": {
                    "expansebusinessunits": [
                        "DevRel"
                    ],
                    "expansedateadded": "2020-10-19T03:59:49.138Z",
                    "expansednsresolutionstatus": [
                        "HAS_DNS_RESOLUTION"
                    ],
                    "expansefirstobserved": "2020-10-17T14:56:11Z",
                    "expanselastobserved": "2020-10-17T14:56:11Z",
                    "expanselastsampledip": "1.2.3.4",
                    "expanseprovidername": null,
                    "expanseservicestatus": [
                        "NO_ACTIVE_SERVICE",
                        "NO_ACTIVE_ON_PREM_SERVICE",
                        "NO_ACTIVE_CLOUD_SERVICE"
                    ],
                    "expansesourcedomain": "pan.dev",
                    "expansetags": [],
                    "expansetenantname": "Palo Alto Networks",
                    "firstseenbysource": "2020-10-17T14:56:11Z",
                    "lastseenbysource": "2020-10-17T14:56:11Z"
                },
                "rawJSON": {...},
                "score": 0,
                "type": "Domain",
                "value": "test.pan.dev"
            }
        ]
    }
}
```

#### Human Readable Output

>### Expanse Indicators (capped at 1)
>|value|type|rawJSON|score|
>|---|---|---|---|
>| 1.2.3.4 | IP | ip: 1.2.3.4<br/>... | 0 |
>| B4YDxJd6wEIcPVsOE7iRdA== | ExpanseCertificate | id: 42b7b646-b35c-32a7-ad1c-beefbeef<br/>... | 0 |
>| test.pan.dev | Domain | id: fdf85c14-97b6-332b-9229-beefbeef<br/>... | 0 |

