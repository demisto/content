This integration will enrich IP addresses from IP-API with data about the geolocation, as well as a determination of the IP address being associated with a mobile device, hosting or proxy. Revers DNS is also returned.

This service is available for free (with a throttle) - or paid.

This integration was integrated and tested with IP-API

## Configure IP-API in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Use HTTPS to communicate with the API | Use of HTTPS requires an API key | False |
| API Key | Only required to bypass rate limits and/or use HTTPS | False |
| Fields to return | See https://members.ip-api.com/docs/json for details | True |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Return IP information


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP-API.continentCode | string | continentCode | 
| IP-API.zip | string | zip | 
| IP-API.mobile | boolean | mobile | 
| IP-API.reverse | string | reverse | 
| IP-API.countryCode | string | countryCode | 
| IP-API.org | string | org | 
| IP-API.isp | string | isp | 
| IP-API.currentTime | string | currentTime | 
| IP-API.query | string | query | 
| IP-API.city | string | city | 
| IP-API.lon | number | lon | 
| IP-API.proxy | boolean | proxy | 
| IP-API.district | string | district | 
| IP-API.countryCode3 | string | countryCode3 | 
| IP-API.currency | string | currency | 
| IP-API.callingCode | number | callingCode | 
| IP-API.as | string | as | 
| IP-API.status | string | status | 
| IP-API.offset | string | offset | 
| IP-API.continent | string | continent | 
| IP-API.region | string | region | 
| IP-API.country | string | country | 
| IP-API.timezone | string | timezone | 
| IP-API.hosting | boolean | hosting | 
| IP-API.asname | string | asname | 
| IP-API.lat | number | lat | 
| IP-API.regionName | string | regionName | 
| DBotScore.Indicator | The indicator that was tested. | String |
| DBotScore.Score | The actual score. | Number |
| DBotScore.Type | The type of indicator. | String |
| DBotScore.Vendor | The vendor used to calculate the score. | String |
| DBotScore.Reliability | Reliability of the source providing the intelligence data. | String |

#### Command Example
```!ip ip=8.8.8.8```

#### Human Readable Output

