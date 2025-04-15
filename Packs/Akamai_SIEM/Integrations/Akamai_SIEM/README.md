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
    | Fetch limit | False | Limit on the number of incidents retrieved in a single fetch. The maximum is 80k.|
    | Akamai Page size | False | The number of events to fetch per request to akamai (multiple requests are made for each fetch). If you're getting aggregated delays, increase the number. The maximum is 80,000. |
    | Skip events decoding | False | Use this parameter to avoid decoding the http message and attack data fields and speed up the ingestion rate. |
    | Long running instance | False | This is a beta feature for high performance fetch events. Use this param only if advised by CS. Make sure this feature is not used with fetch events configured in the integration params and that there's no config ID used for 2 different instances / features. |
    | Page Size - high performance mode | False | The number of events to fetch per request to akamai Default is 200k, maximum is 600k as per Akamai documentation. Use this only when using the long running beta feature. |
    | Max allowed concurrent tasks | False | The number of tasks that can run concurrently - the higher the number, the bigger the gap between the ingested events and the events pulled from akamai can be. Maximum is 10k. Use this only when using the long running beta feature. |
    | Trust any certificate (not secure) | False | |
    | Use system proxy settings | False | |

4. Click **Test** to validate the new instance.

## Commands

You can execute these commands from the CLI, as part of a script, or in a playbook.

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
| time_stamp | Timestamp of events (`<number> <time unit>`. For example, 12 hours, 7 days). | Optional | 

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

##### Context Example

```json
{
  "Akamai": {
    "SIEM": [
        {
            "AttackData": {
                "ClientIP": "8.8.8.8",
                "ConfigID": "50170",
                "PolicyID": "1234_89452",
                "RuleActions": [
                    "alert",
                    "deny"
                ],
                "RuleMessages": [
                    "Custom_RegEX_Rule",
                    "No Accept Header AND No User Agent Header"
                ],
                "RuleTags": [
                    "example",
                    "No-AH-UA"
                ],
                "Rules": [
                    "642118",
                    "642119"
                ]
            },
            "Geo": {
                "Asn": "16509",
                "City": "FRANKFURT",
                "Continent": "EU",
                "Country": "DE",
                "RegionCode": "HE"
            },
            "HttpMessage": {
                "Bytes": "296",
                "Host": "wordpress.panw.ninja",
                "Method": "POST",
                "Path": "/wp-cron.php",
                "Port": "80",
                "Protocol": "HTTP/1.1",
                "RequestHeaders": "Host",
                "RequestId": "87bb604",
                "ResponseHeaders": "Server",
                "Start": "1576746102",
                "Status": "403"
            }
        },
        {
            "AttackData": {
                "ClientIP": "8.8.8.8",
                "ConfigID": "50170",
                "PolicyID": "1234_89452",
                "RuleActions": [
                    "alert",
                    "deny"
                ],
                "RuleMessages": [
                    "Custom_RegEX_Rule",
                    "No Accept Header AND No User Agent Header"
                ],
                "RuleTags": [
                    "example",
                    "No-AH-UA"
                ],
                "Rules": [
                    "642118",
                    "642119"
                ]
            },
            "Geo": {
                "Asn": "16509",
                "City": "FRANKFURT",
                "Continent": "EU",
                "Country": "DE",
                "RegionCode": "HE"
            },
            "HttpMessage": {
                "Bytes": "296",
                "Host": "wordpress.panw.ninja",
                "Method": "POST",
                "Path": "/wp-cron.php",
                "Port": "80",
                "Protocol": "HTTP/1.1",
                "RequestHeaders": "Header",
                "RequestId": "32e63ee2",
                "ResponseHeaders": "Server",
                "Start": "1576746179",
                "Status": "403"
            }
        }
    ]
  },
  "IP": [
    {
      "ASN": "5650",
      "Address": "8.8.8.8",
      "Geo": {
        "Country": "US"
      }
    },
    {
      "ASN": "5650",
      "Address": "8.8.8.8",
      "Geo": {
        "Country": "US"
      }
    }
  ]
}
```

### Troubleshooting

## receiving 416 error code / aggregated delay when fetching events:

This may be due to not querying for enough events per interval / request.
The proposed solution in that case is to use the two parameters **Fetch limit** and **Akamai Page size**.
**Fetch limit** is the number of total events we want to retrieve each fetch interval. Note that the maximum allowed value is 80k.
Note that in cases where the ingestion rate from the Akamai API is higher, the integration will detect it and trigger the next fetch immediately.

**Akamai Page size** configures the number of events to retrieve per request. Note that the maximum allowed value is 80k.
A single fetch interval may execute multiple requests, so configure **Akamai Page size** < **Fetch limit**

If after readjusting the limits you keep encounter errors, please refer to the support.

### Known limitations

## The config ID can only be configured on one instance:

Due to limitations from Akamai, the config ID can only be configured on one instance on the same machine or on different machines (i.e. the same config ID can't be configured both on dev and prod tenants or twice on the same tenant).
Configuring on multiple machines may lead to duplications or missing events.