This integration will enrich IP addresses from IP-API with data about the geolocation, as well as a determination of the IP address being associated with a mobile device, hosting or proxy. Revers DNS is also returned.

This service is available for free (with a throttle) - or paid.

This integration was integrated and tested with version 1.0 of IP-API

## Configure IP-API on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IP-API.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Use HTTPS to communicate with the API | Use of HTTPS requires an API key | False |
    | API Key | Only required to bypass rate limits and/or use HTTPS | False |
    | Fields to return | See https://members.ip-api.com/docs/json for details | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |


4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Return IP information

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP-API.continentCode | String | continentCode | 
| IP-API.zip | String | zip | 
| IP-API.mobile | Boolean | mobile | 
| IP-API.reverse | String | reverse | 
| IP-API.countryCode | String | countryCode | 
| IP-API.org | String | org | 
| IP-API.isp | String | isp | 
| IP-API.currentTime | String | currentTime | 
| IP-API.query | String | query | 
| IP-API.city | String | city | 
| IP-API.lon | Number | lon | 
| IP-API.proxy | Boolean | proxy | 
| IP-API.district | String | district | 
| IP-API.countryCode3 | String | countryCode3 | 
| IP-API.currency | String | currency | 
| IP-API.callingCode | Number | callingCode | 
| IP-API.as | String | as | 
| IP-API.status | String | status | 
| IP-API.offset | String | offset | 
| IP-API.continent | String | continent | 
| IP-API.region | String | region | 
| IP-API.country | String | country | 
| IP-API.timezone | String | timezone | 
| IP-API.hosting | Boolean | hosting | 
| IP-API.asname | String | asname | 
| IP-API.lat | Number | lat | 
| IP-API.regionName | String | regionName | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | String | IP address. | 
