Get security event from [Akamai Web Application Firewall (WAF)](https://www.akamai.com/us/en/resources/waf.jsp) service. This integration was integrated and tested with [API version 1.0 of Akamai WAF SIEM](https://developer.akamai.com/api/cloud_security/siem/v1.html)

## Use Cases
---
- Get security events from Akamai WAF.
- Analyze security events generated on the Akamai platform and correlate them with security events generated from other sources in Cortex XSOAR


## Detailed Description
___
A WAF (web application firewall) is a filter that protects against HTTP application attacks. It inspects HTTP traffic
before it reaches your application and protects your server by filtering out threats that could damage your site functionality or compromise data.

## How to generate API key
---
1. Go to `WEB & DATA CENTER SECURITY`>`Security Configuration`>choose you configuration>`Advanced settings`> Enable SIEM integration.
2. [Open Control panel](https://control.akamai.com/) and login with admin account.
3. Open `identity and access management` menu.
4. Create user with assign roles `Manage SIEM` or make sure the admin has rights for manage SIEM.
5. Log in to new account you created in the last step.
6. Open `identity and access management` menu.
7. Create `new api client for me`
8. Assign API key to the relevant users group, and assign on next page <code>Read/Write</code> access for <code>SIEM</
9. Save configuration and go to API detail you created.
10. Press `new credentials` and download or copy it.
11. Now use the credentials for configure Akamai WAF in Cortex XSOAR

## Configure Akamai WAF SIEM on Cortex XSOAR
---
1.  Navigate to **Settings** > **Integrations**  > **Servers & Services**.
2.  Search for Akamai WAF SIEM.
3.  Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL (e.g. https://example.net) |  | True |
    | Client token |  | False |
    | Access token |  | False |
    | Client secret |  | False |
    | Config IDs to fetch for fetch alerts | Config IDs to fetch for fetch alerts, can have multiple separated by semi commas ';' | False |
    | Incident type |  | False |
    | First fetch timestamp (for example 12 hours, 7 days) |  | False |
    | Fetch limit for fetch alerts (minimum is 20) |  | False |
    | Fetch incidents |  | False |
    | Fetch Events | Fetch events as xsiam events, in addition to the alerts, default is True. |  |
    | Events Fetch Interval |  | How often fetch events should run. |
    | Config IDs to fetch (Relevant only for xsiam) | Config IDs to fetch - mandatory field when setting integration in xsiam. | False |
    | Maximum events to fetch (Relevant only for xsiam) |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
4.  Click **Test** to validate the new instance.

<h2>Fetch Incidents</h2>
<pre>
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
            "policyId": "1234",
            "clientIP": "8.8.8.8",
            "rules": "test",
            "ruleVersions": "",
            "ruleMessages": "Test",
            "ruleTags": "Test",
            "ruleData": "",
            "ruleSelectors": "",
            "ruleActions": "Test"
          },
          "httpMessage": {
            "requestId": "3fbce3e",
            "start": "1576002507",
            "protocol": "HTTP/1.1",
            "method": "HEAD",
            "host": "google.com",
            "port": "80",
            "path": "index",
            "requestHeaders": "Test",
            "status": "403",
            "bytes": "0",
            "responseHeaders": "Server"
          },
          "geo": {
            "continent": "NA",
            "country": "US",
            "city": "LOSANGELES",
            "regionCode": "CA",
            "asn": "5650"
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
            "policyId": "1234",
            "clientIP": "8.8.8.8",
            "rules": "test",
            "ruleVersions": "",
            "ruleMessages": "Test",
            "ruleTags": "Test",
            "ruleData": "",
            "ruleSelectors": "",
            "ruleActions": "Test"
          },
          "httpMessage": {
            "requestId": "3fbd757",
            "start": "1576002506",
            "protocol": "HTTP/1.1",
            "method": "HEAD",
            "host": "google.com",
            "port": "80",
            "path": "index",
            "requestHeaders": "Test",
            "status": "403",
            "bytes": "0",
            "responseHeaders": "Server"
          },
          "geo": {
            "continent": "NA",
            "country": "US",
            "city": "LOSANGELES",
            "regionCode": "CA",
            "asn": "5650"
          }
        }
      }
    ]

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### akamai-siem-get-events

***
Get security events from Akamai WAF

#### Base Command

`akamai-siem-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_ids | Unique identifier for each security configuration. To report on more than one configuration, separate  integer identifiers with semicolons, e.g. 12892;29182;82912. | Required |
| offset | This token denotes the last message. If specified, this operation fetches only security events that have occurred from offset. This is a required parameter for offset mode and you can’t use it in time-based requests. | Optional |
| limit | Defines the approximate maximum number of security events each fetch returns. | Optional |
| from_epoch | The start of a specified time range, expressed in Unix epoch seconds. | Optional |
| to_epoch | The end of a specified time range, expressed in Unix epoch seconds. | Optional |
| timestamp | timestamp (for example 12 hours, 7 days of events. | Optional |

## Additional Information
Allowed query parameters combinations:
- offset - Since a prior request.
- offset, limit - Since a prior request, limited.
- from - Since a point in time.
- from, limit - Since a point in time, limited.
- from, to - Over a range of time.
- from, to, limit - Over a range of time, limited.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.SIEM.AttackData.clientIP | String | IP involved in the attack. |
| Akamai.SIEM.AttackData.ConfigID | String | Unique identifier of security configuration involved. |
| Akamai.SIEM.AttackData.PolicyID | String | Unique identifier of Policy configuration involved. |
| Akamai.SIEM.AttackData.PolicyID | String | Policy ID triggered. |
| Akamai.SIEM.AttackData.Geo.Asn | String | Geographic ASN location of involved IP. |
| Akamai.SIEM.AttackData.Geo.City | String | City of involved IP. |
| Akamai.SIEM.AttackData.Geo.Continent | String | Continent of involved IP. |
| Akamai.SIEM.AttackData.Geo.Country | String | Country of involved IP. |
| Akamai.SIEM.AttackData.Geo.RegionCode | String | Region code of involved IP. |
| Akamai.SIEM.AttackData.HttpMessage.Bytes | Number | HTTP message size in bytes. |
| Akamai.SIEM.AttackData.HttpMessage.Host | String | HTTP message host. |
| Akamai.SIEM.AttackData.HttpMessage.Method | String | HTTP message method. |
| Akamai.SIEM.AttackData.HttpMessage.Path | String | HTTP message path. |
| Akamai.SIEM.AttackData.HttpMessage.Port | String | HTTP message port. |
| Akamai.SIEM.AttackData.HttpMessage.Protocol | String | HTTP message protocol. |
| Akamai.SIEM.AttackData.HttpMessage.Query | String | HTTP message query. |
| Akamai.SIEM.AttackData.HttpMessage.RequestHeaders | String | HTTP message request headers. |
| Akamai.SIEM.AttackData.HttpMessage.RequestID | String | HTTP message request ID. |
| Akamai.SIEM.AttackData.HttpMessage.ResponseHeaders | String | HTTP message response headers. |
| Akamai.SIEM.AttackData.HttpMessage.Start | Date | HTTP message epoch start time. |
| Akamai.SIEM.AttackData.HttpMessage.Status | Number | HTTP message status code. |
| IP.Address | String | IP address |
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". |
| IP.Geo.Country | String | The country in which the IP address is located |

## Command Example
`!akamai-siem-get-events config_ids="50170" period="3 hours"`

Context Example
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
                "Host": "wordpress.demisto.ninja",
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
                "Host": "wordpress.demisto.ninja",
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


### Akamai SIEM - Attacks list
| Attacking IP | Config ID | Date occured | Location | Policy ID | Rule actions | Rule messages | Rules |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 3.124.101.138 | 50170 | 2019-12-19T09:00:42Z | Country: DE City: FRANKFURT | 1234_89452 | alert, deny | Custom_RegEX_Rule,No Accept Header AND No User Agent Header | 642118,642119 |