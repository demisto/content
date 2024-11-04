# Get security event from [Akamai Web Application Firewall (WAF)](https://www.akamai.com/us/en/resources/waf.jsp) service.

This integration was integrated and tested with [API version 1.0 of Akamai WAF SIEM](https://developer.akamai.com/api/cloud_security/siem/v1.html).

## Use Cases

- Get security events from Akamai WAF.
- Analyze security events generated on the Akamai platform and correlate them with security events generated from other sources in Cortex XSOAR.

## Detailed Description

A WAF (web application firewall) is a filter that protects against HTTP application attacks. It inspects HTTP traffic before it reaches your application and protects your server by filtering out threats that could damage your site functionality or compromise data.

## API keys generating steps

1. Go to `WEB & DATA CENTER SECURITY` > `Security Configuration` > choose your configuration > `Advanced settings` > Enable SIEM integration.
2. [Open Control panel](https://control.akamai.com/) and login with admin account.
3. Open `identity and access management` menu.
4. Create a user with assigned roles `Manage SIEM` or make sure the admin has rights to manage SIEM.
5. Log in to the new account you created in the last step.
6. Open `identity and access management` menu.
7. Create `new api client for me`.
8. Assign an API key to the relevant user group, and on the next page assign `Read/Write` access for `SIEM`.
9. Save configuration and go to the API detail you created.
10. Press `new credentials` and download or copy it.
11. Now use the credentials to configure Akamai WAF in Cortex XSOAR.

## Configure Akamai WAF SIEM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Akamai WAF SIEM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** | |
    | --- | --- | --- |
    | Server URL (e.g., <https://example.net>) | True | |
    | Client token | False | |
    | Access token | False | |
    | Client secret | False | |
    | Config ids to fetch | True | |
    | Incident type | False | |
    | First fetch timestamp | False | |
    | Fetch limit | False | Limit on the number of incidents retrieved in a single fetch. |
    | Page size | False | The number of events to fetch per request - the maximum is 600k, raise this parameter in case you're getting aggregated delays. |
    | Trust any certificate (not secure) | False | |
    | Use system proxy settings | False | |

4. Click **Test** to validate the new instance.

## Fetch Incidents

```json
[
    {
        "name": "Akamai SIEM: 50170",
        "occurred": "2019-12-10T18:28:27Z",
        "rawJSON": {
            "type": "akamai_siem",
            "format": "json",
            "version": "1.0",
            "attackData": {
                "configId": "50170",
                ...
            }
        }
    },
    {
        "name": "Akamai SIEM: 50170",
        "occurred": "2019-12-10T18:28:26Z",
        "rawJSON": {
            "type": "akamai_siem",
            "format": "json",
            "version": "1.0",
            "attackData": {
                "configId": "50170",
                ...
            }
        }
    }
]
```

## akamai-siem-reset-offset

***
Reset the last offset in case the offset is invalid.

#### Base Command

`akamai-siem-reset-offset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### akamai-siem-get-events
***
Get security events from Akamai WAF.


#### Base Command

`akamai-siem-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_ids | Unique identifier for each security configuration. To report on more than one configuration, separate the integer identifiers with semicolons (;), for example: 12892;29182;82912. | Required | 
| offset | This token denotes the last message. If specified, this operation fetches only security events that have occurred from the offset. This is a required parameter for offset mode and you can’t use it in time-based requests | Optional | 
| limit | Defines the maximum number of security events returned per fetch. | Optional | 
| from_epoch | The start of a specified time range, expressed in Unix epoch seconds. | Optional | 
| to_epoch | The end of a specified time range, expressed in Unix epoch seconds. | Optional | 
| time_stamp | Timestamp of events (<number> <time unit>. For example, 12 hours, 7 days. | Optional | 

#### Context Output

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.SIEM.AttackData.clientIP | String | IP address involved in the attack. | 
| Akamai.SIEM.AttackData.ConfigID | String | Unique identifier of the security configuration involved. | 
| Akamai.SIEM.AttackData.PolicyID | String | Unique identifier of the policy configuration involved. | 
| Akamai.SIEM.AttackData.Geo.Asn | String | Geographic ASN location of the IP address involved in the attack. | 
| Akamai.SIEM.AttackData.Geo.City | String | City of the IP address involved in the attack. | 
| Akamai.SIEM.AttackData.Geo.Continent | String | Continent of the IP address involved in the attack. | 
| Akamai.SIEM.AttackData.Geo.Country | String | Country of the IP address involved in the attack. | 
| Akamai.SIEM.AttackData.Geo.RegionCode | String | Region code of the IP address involved in the attack. | 
| Akamai.SIEM.AttackData.HttpMessage.Bytes | Number | HTTP messege size in bytes. | 
| Akamai.SIEM.AttackData.HttpMessage.Host | String | HTTP messege host. | 
| Akamai.SIEM.AttackData.HttpMessage.Method | String | HTTP messege method. | 
| Akamai.SIEM.AttackData.HttpMessage.Path | String | HTTP messege path. | 
| Akamai.SIEM.AttackData.HttpMessage.Port | String | HTTP messege port. | 
| Akamai.SIEM.AttackData.HttpMessage.Protocol | String | HTTP messege protocol. | 
| Akamai.SIEM.AttackData.HttpMessage.Query | String | HTTP messege query. | 
| Akamai.SIEM.AttackData.HttpMessage.RequestHeaders | String | HTTP messege request headers. | 
| Akamai.SIEM.AttackData.HttpMessage.RequestID | String | HTTP messege request ID. | 
| Akamai.SIEM.AttackData.HttpMessage.ResponseHeaders | String | HTTP message response headers. | 
| Akamai.SIEM.AttackData.HttpMessage.Start | Date | HTTP messege epoch start time. | 
| Akamai.SIEM.AttackData.HttpMessage.Status | Number | HTTP messege status code. | 
| IP.Address | String | IP address. | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
