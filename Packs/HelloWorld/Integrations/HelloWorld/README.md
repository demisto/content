~~~~This is the Hello World integration for getting started and learn how to build an integration with Cortex XSOAR.
You can check the Design Document of this integration [here](https://docs.google.com/document/d/1wETtBEKg37PHNU8tYeB56M1LE314ux086z3HFeF_cX0).

Please make sure you look at the integration source code and comments.

This integration was built to interact with the sample SOAR Hello World API To check the API source code go to [GitHub](https://github.com/fvigo/soarhelloworld).

## Configure HelloWorld on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HelloWorld.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://soar.monstersofhack.com\) | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| max_fetch | Maximum number of incidents per fetch | False |
| apikey | API Key | True |
| threshold_ip | Score threshold for ip reputation command \(0\-100\) | False |
| threshold_domain | Score threshold for domain reputation command \(0\-100\) | False |
| alert_status | Fetch alerts with status \(ACTIVE, CLOSED\) | False |
| alert_type | Fetch alerts with type | False |
| min_severity | Minimum severity of alerts to fetch | True |
| first_fetch | First fetch time | False |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### helloworld-say-hello
***
Hello command - prints hello to anyone.


#### Base Command

`helloworld-say-hello`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of whom you want to say hello to. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| hello | String | Should be Hello \*\*something\*\* here. | 


#### Command Example
```!helloworld-say-hello name="Hello Dbot"```

#### Context Example
```
{
    "hello": "Hello Hello Dbot"
}
```

#### Human Readable Output

>## Hello Hello Dbot

### helloworld-search-alerts
***
Search HelloWorld Alerts.


#### Base Command

`helloworld-search-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | Filter by alert severity. Comma-separated value (Low,Medium,High,Critical) | Optional | 
| status | Filter by alert status. | Optional | 
| alert_type | Filter by alert type | Optional | 
| max_results | Maximum results to return. | Optional | 
| start_time | Filter by start time. <br/>Examples:<br/>  "3 days ago"<br/>  "1 month"<br/>  "2019-10-10T12:22:00"<br/>  "2019-10-10" | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Alert.alert_id | String | Alert ID. | 
| HelloWorld.Alert.alert_status | String | Alert status. Can be 'ACTIVE' or 'CLOSED'. | 
| HelloWorld.Alert.alert_type | String | Alert type. For example 'Bug' or 'Vulnerability'. | 
| HelloWorld.Alert.created | Date | Alert created time. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| HelloWorld.Alert.name | String | Alert name. | 
| HelloWorld.Alert.severity | String | Alert severity. Can be 'Low', 'Medium', 'High' or 'Critical'. | 


#### Command Example
```!helloworld-search-alerts severity="Critical" start_time="3 days" max_results=2 status="ACTIVE"```

#### Context Example
```
{
    "HelloWorld": {
        "Alert": [
            {
                "alert_id": "158cfeb2-84bf-498d-a10d-a55c3445d76e",
                "alert_status": "ACTIVE",
                "alert_type": "Feature",
                "created": "2020-05-06T20:39:07.000Z",
                "name": "Hello World Alert of type Feature",
                "severity": "Critical"
            },
            {
                "alert_id": "c61eec7e-3114-46e2-be71-a82572b98fc3",
                "alert_status": "ACTIVE",
                "alert_type": "Bug",
                "created": "2020-05-06T07:49:51.000Z",
                "name": "Hello World Alert of type Bug",
                "severity": "Critical"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|alert_id|alert_status|alert_type|created|name|severity|
>|---|---|---|---|---|---|
>| 158cfeb2-84bf-498d-a10d-a55c3445d76e | ACTIVE | Feature | 2020-05-06T20:39:07.000Z | Hello World Alert of type Feature | Critical |
>| c61eec7e-3114-46e2-be71-a82572b98fc3 | ACTIVE | Bug | 2020-05-06T07:49:51.000Z | Hello World Alert of type Bug | Critical |


### helloworld-get-alert
***
Retrieve alert extra data by ID.


#### Base Command

`helloworld-get-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Alert.alert_id | String | Alert ID. | 
| HelloWorld.Alert.created | Date | Alert created time. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| HelloWorld.Alert.description | String | Alert description. | 
| HelloWorld.Alert.device_id | String | ID of the device involved in the alert. | 
| HelloWorld.Alert.device_ip | String | IP Address of the device involved in the alert. | 
| HelloWorld.Alert.location | String | Location of the device involved in the alert. | 
| HelloWorld.Alert.user | String | User involved in the alert. | 


#### Command Example
```!helloworld-get-alert alert_id=695b3238-05d6-4934-86f5-9fff3201aeb0```

#### Context Example
```
{
    "HelloWorld": {
        "Alert": {
            "alert_id": "695b3238-05d6-4934-86f5-9fff3201aeb0",
            "created": "2020-05-08T22:21:01.000Z",
            "description": "Your processor has processed too many instructions.  Turn it off immediately, do not type any commands!!",
            "device_id": "d3c06d55-0adc-4c60-bf40-8316006ae954",
            "device_ip": "76.224.87.171",
            "location": "Medina Station",
            "user": "Sugar Man"
        }
    }
}
```

#### Human Readable Output

>### HelloWorld Alert 695b3238-05d6-4934-86f5-9fff3201aeb0
>|alert_id|created|description|device_id|device_ip|location|user|
>|---|---|---|---|---|---|---|
>| 695b3238-05d6-4934-86f5-9fff3201aeb0 | 2020-05-08T22:21:01.000Z | Your processor has processed too many instructions.  Turn it off immediately, do not type any commands!! | d3c06d55-0adc-4c60-bf40-8316006ae954 | 76.224.87.171 | Medina Station | Sugar Man |


### helloworld-update-alert-status
***
Update the status for an alert.


#### Base Command

`helloworld-update-alert-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID to update. | Required | 
| status | New status of the alert. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Alert.alert_id | String | Alert ID. | 
| HelloWorld.Alert.updated | Date | Alert update time. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| HelloWorld.Alert.alert_status | String | Alert status. Can be 'ACTIVE' or 'CLOSED'. | 


#### Command Example
```!helloworld-update-alert-status alert_id=695b3238-05d6-4934-86f5-9fff3201aeb0 status="CLOSED"```

#### Context Example
```
{
    "HelloWorld": {
        "Alert": {
            "alert_id": "695b3238-05d6-4934-86f5-9fff3201aeb0",
            "alert_status": "CLOSED",
            "updated": "2020-05-08T22:21:05.000Z"
        }
    }
}
```

#### Human Readable Output

>### HelloWorld Alert 695b3238-05d6-4934-86f5-9fff3201aeb0
>|alert_id|alert_status|updated|
>|---|---|---|
>| 695b3238-05d6-4934-86f5-9fff3201aeb0 | CLOSED | 2020-05-08T22:21:05.000Z |


### ip
***
Return IP information and reputation


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 
| threshold | If the IP has reputation above the threshold then the IP defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| HelloWorld.IP.asn | String | The autonomous system name for the IP address. | 
| HelloWorld.IP.asn_cidr | String | The ASN CIDR. | 
| HelloWorld.IP.asn_country_code | String | The ASN country code. | 
| HelloWorld.IP.asn_date | Date | The date on which the ASN was assigned. | 
| HelloWorld.IP.asn_description | String | The ASN description. | 
| HelloWorld.IP.asn_registry | String | The registry the ASN belongs to. | 
| HelloWorld.IP.entities | String | Entities associated to the IP. | 
| HelloWorld.IP.ip | String | The actual IP address. | 
| HelloWorld.IP.network.cidr | String | Network CIDR for the IP address. | 
| HelloWorld.IP.network.country | Unknown | The country of the IP address. | 
| HelloWorld.IP.network.end_address | String | The last IP address of the CIDR. | 
| HelloWorld.IP.network.events.action | String | The action that happened on the event. | 
| HelloWorld.IP.network.events.actor | Unknown | The actor that performed the action on the event. | 
| HelloWorld.IP.network.events.timestamp | String | The timestamp when the event occurred. | 
| HelloWorld.IP.network.handle | String | The handle of the network. | 
| HelloWorld.IP.network.ip_version | String | The IP address version. | 
| HelloWorld.IP.network.links | String | Links associated to the IP address. | 
| HelloWorld.IP.network.name | String | The name of the network. | 
| HelloWorld.IP.network.notices.description | String | The description of the notice. | 
| HelloWorld.IP.network.notices.links | Unknown | Links associated with the notice. | 
| HelloWorld.IP.network.notices.title | String | Title of the notice. | 
| HelloWorld.IP.network.parent_handle | String | Handle of the parent network. | 
| HelloWorld.IP.network.raw | Unknown | Additional raw data for the network. | 
| HelloWorld.IP.network.remarks | Unknown | Additional remarks for the network. | 
| HelloWorld.IP.network.start_address | String | The first IP address of the CIDR. | 
| HelloWorld.IP.network.status | String | Status of the network. | 
| HelloWorld.IP.network.type | String | The type of the network. | 
| HelloWorld.IP.query | String | IP address that was queried. | 
| HelloWorld.IP.raw | Unknown | Additional raw data for the IP address. | 
| HelloWorld.IP.score | Number | Reputation score from HelloWorld for this IP \(0 to 100, where higher is worse\). | 
| IP.Address | String | IP address. | 
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. | 
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. | 
| IP.ASN | String | The autonomous system name for the IP address. | 


#### Command Example
```!ip ip="8.8.8.8"```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 2,
        "Type": "ip",
        "Vendor": "HelloWorld"
    },
    "HelloWorld": {
        "IP": {
            "asn": "15169",
            "asn_cidr": "8.8.8.0/24",
            "asn_country_code": "US",
            "asn_date": "1992-12-01",
            "asn_description": "GOOGLE, US",
            "asn_registry": "arin",
            "entities": [
                "GOGL"
            ],
            "ip": "8.8.8.8",
            "network": {
                "cidr": "8.8.8.0/24",
                "country": null,
                "end_address": "8.8.8.255",
                "events": [
                    {
                        "action": "last changed",
                        "actor": null,
                        "timestamp": "2014-03-14T15:52:05-04:00"
                    },
                    {
                        "action": "registration",
                        "actor": null,
                        "timestamp": "2014-03-14T15:52:05-04:00"
                    }
                ],
                "handle": "NET-8-8-8-0-1",
                "ip_version": "v4",
                "links": [
                    "https://rdap.arin.net/registry/ip/8.8.8.0",
                    "https://whois.arin.net/rest/net/NET-8-8-8-0-1",
                    "https://rdap.arin.net/registry/ip/8.0.0.0/9"
                ],
                "name": "LVLT-GOGL-8-8-8",
                "notices": [
                    {
                        "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                        "links": [
                            "https://www.arin.net/resources/registry/whois/tou/"
                        ],
                        "title": "Terms of Service"
                    },
                    {
                        "description": "If you see inaccuracies in the results, please visit: ",
                        "links": [
                            "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                        ],
                        "title": "Whois Inaccuracy Reporting"
                    },
                    {
                        "description": "Copyright 1997-2020, American Registry for Internet Numbers, Ltd.",
                        "links": null,
                        "title": "Copyright Notice"
                    }
                ],
                "parent_handle": "NET-8-0-0-0-1",
                "raw": null,
                "remarks": null,
                "start_address": "8.8.8.0",
                "status": [
                    "active"
                ],
                "type": "ALLOCATION"
            },
            "query": "8.8.8.8",
            "raw": null,
            "score": 45
        }
    },
    "IP": {
        "ASN": "15169",
        "Address": "8.8.8.8"
    }
}
```

#### Human Readable Output

>### IP List
>|asn|asn_cidr|asn_country_code|asn_date|asn_description|asn_registry|entities|ip|network|query|raw|score|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 15169 | 8.8.8.0/24 | US | 1992-12-01 | GOOGLE, US | arin | GOGL | 8.8.8.8 | handle: NET-8-8-8-0-1<br/>status: active<br/>remarks: null<br/>notices: {'title': 'Terms of Service', 'description': 'By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use', 'links': ['https://www.arin.net/resources/registry/whois/tou/']},<br/>{'title': 'Whois Inaccuracy Reporting', 'description': 'If you see inaccuracies in the results, please visit: ', 'links': ['https://www.arin.net/resources/registry/whois/inaccuracy_reporting/']},<br/>{'title': 'Copyright Notice', 'description': 'Copyright 1997-2020, American Registry for Internet Numbers, Ltd.', 'links': None}<br/>links: https://rdap.arin.net/registry/ip/8.8.8.0,<br/>https://whois.arin.net/rest/net/NET-8-8-8-0-1,<br/>https://rdap.arin.net/registry/ip/8.0.0.0/9<br/>events: {'action': 'last changed', 'timestamp': '2014-03-14T15:52:05-04:00', 'actor': None},<br/>{'action': 'registration', 'timestamp': '2014-03-14T15:52:05-04:00', 'actor': None}<br/>raw: null<br/>start_address: 8.8.8.0<br/>end_address: 8.8.8.255<br/>cidr: 8.8.8.0/24<br/>ip_version: v4<br/>type: ALLOCATION<br/>name: LVLT-GOGL-8-8-8<br/>country: null<br/>parent_handle: NET-8-0-0-0-1 | 8.8.8.8 |  | 45 |


### domain
***
Returns Domain information and reputation.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Optional | 
| threshold | If the domain has reputation above the threshold then the domain defined as malicious. If threshold not set, then threshold from instance configuration is used. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.Organization | String | The organization of the domain. | 
| Domain.CreationDate | Date | The creation date of the domain. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| Domain.ExpirationDate | Date | The expiration date of the domain. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| Domain.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| Domain.NameServers | String | Name servers of the domain. | 
| Domain.WHOIS.NameServers | String | A CSV string of name servers, for example 'ns1.bla.com, ns2.bla.com'. | 
| Domain.WHOIS.CreationDate | Date | The creation date of the domain. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| Domain.WHOIS.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example 'GoDaddy' | 
| IP.ASN | String | The autonomous system name for the IP address. | 
| HelloWorld.Domain.address | String | Domain admin address. | 
| HelloWorld.Domain.city | String | Domain admin city. | 
| HelloWorld.Domain.country | String | Domain admin country. | 
| HelloWorld.Domain.creation_date | Date | Domain creation date. Format is ISO8601. | 
| HelloWorld.Domain.dnssec | String | DNSSEC status. | 
| HelloWorld.Domain.domain | String | The domain name. | 
| HelloWorld.Domain.domain_name | String | Domain name options. | 
| HelloWorld.Domain.emails | String | Contact emails. | 
| HelloWorld.Domain.expiration_date | Date | Expiration date. Format is ISO8601. | 
| HelloWorld.Domain.name | String | Domain admin name. | 
| HelloWorld.Domain.name_servers | String | Name server. | 
| HelloWorld.Domain.org | String | Domain organization. | 
| HelloWorld.Domain.referral_url | Unknown | Referral URL. | 
| HelloWorld.Domain.registrar | String | Domain registrar. | 
| HelloWorld.Domain.score | Number | Reputation score from HelloWorld for this domain \(0 to 100, where higher is worse\). | 
| HelloWorld.Domain.state | String | Domain admin state. | 
| HelloWorld.Domain.status | String | Domain status. | 
| HelloWorld.Domain.updated_date | Date | Updated date. Format is ISO8601. | 
| HelloWorld.Domain.whois_server | String | WHOIS server. | 
| HelloWorld.Domain.zipcode | Unknown | Domain admin zipcode. | 


#### Command Example
```!domain domain="demisto.com"```

#### Context Example
```
{
    "DBotScore": {
        "Indicator": "demisto.com",
        "Score": 2,
        "Type": "domain",
        "Vendor": "HelloWorld"
    },
    "Domain": {
        "CreationDate": "2015-01-16T21:36:27.000Z",
        "ExpirationDate": "2026-01-16T21:36:27.000Z",
        "Name": "demisto.com",
        "NameServers": [
            "PNS31.CLOUDNS.NET",
            "PNS32.CLOUDNS.NET",
            "PNS33.CLOUDNS.NET",
            "PNS34.CLOUDNS.NET",
            "pns31.cloudns.net",
            "pns32.cloudns.net",
            "pns33.cloudns.net",
            "pns34.cloudns.net"
        ],
        "Organization": "WhoisGuard, Inc.",
        "Registrant": {
            "Country": "PA",
            "Email": null,
            "Name": "WhoisGuard Protected",
            "Phone": null
        },
        "Registrar": {
            "AbuseEmail": null,
            "AbusePhone": null,
            "Name": "NAMECHEAP INC"
        },
        "UpdatedDate": "2019-05-14T16:14:12.000Z",
        "WHOIS": {
            "CreationDate": "2015-01-16T21:36:27.000Z",
            "ExpirationDate": "2026-01-16T21:36:27.000Z",
            "NameServers": [
                "PNS31.CLOUDNS.NET",
                "PNS32.CLOUDNS.NET",
                "PNS33.CLOUDNS.NET",
                "PNS34.CLOUDNS.NET",
                "pns31.cloudns.net",
                "pns32.cloudns.net",
                "pns33.cloudns.net",
                "pns34.cloudns.net"
            ],
            "Registrant": {
                "Country": "PA",
                "Email": null,
                "Name": "WhoisGuard Protected",
                "Phone": null
            },
            "Registrar": {
                "AbuseEmail": null,
                "AbusePhone": null,
                "Name": "NAMECHEAP INC"
            },
            "UpdatedDate": "2019-05-14T16:14:12.000Z"
        }
    },
    "HelloWorld": {
        "Domain": {
            "address": "P.O. Box 0823-03411",
            "city": "Panama",
            "country": "PA",
            "creation_date": "2015-01-16T21:36:27.000Z",
            "dnssec": "unsigned",
            "domain": "demisto.com",
            "domain_name": [
                "DEMISTO.COM",
                "demisto.com"
            ],
            "emails": [
                "abuse@namecheap.com",
                "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com"
            ],
            "expiration_date": "2026-01-16T21:36:27.000Z",
            "name": "WhoisGuard Protected",
            "name_servers": [
                "PNS31.CLOUDNS.NET",
                "PNS32.CLOUDNS.NET",
                "PNS33.CLOUDNS.NET",
                "PNS34.CLOUDNS.NET",
                "pns31.cloudns.net",
                "pns32.cloudns.net",
                "pns33.cloudns.net",
                "pns34.cloudns.net"
            ],
            "org": "WhoisGuard, Inc.",
            "referral_url": null,
            "registrar": "NAMECHEAP INC",
            "score": 56,
            "state": "Panama",
            "status": "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "updated_date": "2019-05-14T16:14:12.000Z",
            "whois_server": "whois.namecheap.com",
            "zipcode": null
        }
    }
}
```

#### Human Readable Output

>### Domain List
>|address|city|country|creation_date|dnssec|domain|domain_name|emails|expiration_date|name|name_servers|org|referral_url|registrar|score|state|status|updated_date|whois_server|zipcode|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| P.O. Box 0823-03411 | Panama | PA | 2015-01-16T21:36:27.000Z | unsigned | demisto.com | DEMISTO.COM,<br/>demisto.com | abuse@namecheap.com,<br/>5be9245893ff486d98c3640879bb2657.protect@whoisguard.com | 2026-01-16T21:36:27.000Z | WhoisGuard Protected | PNS31.CLOUDNS.NET,<br/>PNS32.CLOUDNS.NET,<br/>PNS33.CLOUDNS.NET,<br/>PNS34.CLOUDNS.NET,<br/>pns31.cloudns.net,<br/>pns32.cloudns.net,<br/>pns33.cloudns.net,<br/>pns34.cloudns.net | WhoisGuard, Inc. |  | NAMECHEAP INC | 56 | Panama | clientTransferProhibited https://icann.org/epp#clientTransferProhibited | 2019-05-14T16:14:12.000Z | whois.namecheap.com |  |


### helloworld-scan-start
***
Start scan on an asset.


#### Base Command

`helloworld-scan-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Asset to start the scan against. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Scan.scan_id | string | Unique ID of the scan. | 
| HelloWorld.Scan.status | string | Status of the scan \('RUNNING' or 'COMPLETE'\). | 
| HelloWorld.Scan.hostname | string | The hostname the scan is run against. | 


#### Command Example
```!helloworld-scan-start hostname="example.com"```

#### Context Example
```
{
    "HelloWorld": {
        "Scan": {
            "hostname": "example.com",
            "scan_id": "22cc5dba-9e61-42c6-8355-94527b9815c6",
            "status": "RUNNING"
        }
    }
}
```

#### Human Readable Output

>Started scan 22cc5dba-9e61-42c6-8355-94527b9815c6

### helloworld-scan-status
***
Retrieve scan status for one or more scan IDs.


#### Base Command

`helloworld-scan-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | List of Scan IDs. helloworld-scan-start returns "scan_id". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Scan.scan_id | string | Unique ID of the scan. | 
| HelloWorld.Scan.status | string | Status of the scan \('RUNNING' or 'COMPLETE'\). | 


#### Command Example
```!helloworld-scan-status scan_id="100"```

#### Context Example
```
{
    "HelloWorld": {
        "Scan": {
            "scan_id": "100",
            "status": "COMPLETE"
        }
    }
}
```

#### Human Readable Output

>### Scan status
>|scan_id|status|
>|---|---|
>| 100 | COMPLETE |


### helloworld-scan-results
***
Retrieve scan status in Context or as a File (default) for a Scan.


#### Base Command

`helloworld-scan-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| format | Results format (file or JSON). | Required | 
| scan_id | Unique ID of the scan. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HelloWorld.Scan.entities.entity-id | String | Scanned entity ID. | 
| HelloWorld.Scan.entities.ip_address | String | Scanned entity IP address. | 
| HelloWorld.Scan.entities.type | String | Scanned entity type. | 
| HelloWorld.Scan.entities.vulnerability_status | String | Scanned entity vulnerability status. | 
| HelloWorld.Scan.entities.vulns | String | Scanned entity CVE. | 
| HelloWorld.Scan.scan_id | String | Unique ID of the scan. | 
| HelloWorld.Scan.status | String | Status of the scan \('RUNNING' or 'COMPLETE'\). | 
| InfoFile.EntryID | Unknown | The EntryID of the report file. | 
| InfoFile.Extension | string | The extension of the report file. | 
| InfoFile.Name | string | The name of the report file. | 
| InfoFile.Info | string | The info of the report file. | 
| InfoFile.Size | number | The size of the report file. | 
| InfoFile.Type | string | The type of the report file. | 
| CVE.ID | string | The ID of the CVE. | 


#### Command Example
```!helloworld-scan-results scan_id=100 format=json```

#### Context Example
```
{
    "CVE": {
        "ID": [
            "CVE-2019-14805",
            "CVE-2019-15472",
            "CVE-2019-0200",
            "CVE-2019-10490",
            "CVE-2019-2658",
            "CVE-2019-8139",
            "CVE-2019-10401",
            "CVE-2019-5989",
            "CVE-2019-2128",
            "CVE-2019-5279",
            "CVE-2019-13507",
            "CVE-2019-5450",
            "CVE-2019-6291",
            "CVE-2019-4811",
            "CVE-2019-9322",
            "CVE-2019-18250",
            "CVE-2019-7169",
            "CVE-2019-18671",
            "CVE-2019-7390",
            "CVE-2019-1716",
            "CVE-2019-10763",
            "CVE-2019-1512",
            "CVE-2019-15485",
            "CVE-2019-12611",
            "CVE-2019-13100",
            "CVE-2019-18824",
            "CVE-2019-2889",
            "CVE-2019-10311",
            "CVE-2019-1003074",
            "CVE-2019-16177",
            "CVE-2019-19767",
            "CVE-2019-3420",
            "CVE-2019-19532",
            "CVE-2019-2946",
            "CVE-2019-10528",
            "CVE-2019-13301",
            "CVE-2019-5252",
            "CVE-2019-7081",
            "CVE-2019-5880",
            "CVE-2019-20443",
            "CVE-2019-0240",
            "CVE-2019-17426",
            "CVE-2019-5250",
            "CVE-2019-20424",
            "CVE-2019-9578",
            "CVE-2019-10481",
            "CVE-2019-4856",
            "CVE-2019-8994",
            "CVE-2019-0335",
            "CVE-2019-6457",
            "CVE-2019-0734",
            "CVE-2019-13339",
            "CVE-2019-1732",
            "CVE-2019-15593",
            "CVE-2019-6579",
            "CVE-2019-15233",
            "CVE-2019-17269",
            "CVE-2019-8654",
            "CVE-2019-9624",
            "CVE-2019-2923",
            "CVE-2019-13524",
            "CVE-2019-9580",
            "CVE-2019-0667",
            "CVE-2019-2610",
            "CVE-2019-5632",
            "CVE-2019-9375",
            "CVE-2019-5114",
            "CVE-2019-12978",
            "CVE-2019-19817",
            "CVE-2019-10479",
            "CVE-2019-12162",
            "CVE-2019-11971",
            "CVE-2019-12762",
            "CVE-2019-0746",
            "CVE-2019-15497",
            "CVE-2019-9025",
            "CVE-2019-10492",
            "CVE-2019-14357",
            "CVE-2019-5763",
            "CVE-2019-5789",
            "CVE-2019-16534",
            "CVE-2019-18241",
            "CVE-2019-11331",
            "CVE-2019-19592",
            "CVE-2019-11632",
            "CVE-2019-8926",
            "CVE-2019-4038",
            "CVE-2019-5095",
            "CVE-2019-16237",
            "CVE-2019-9114",
            "CVE-2019-0757",
            "CVE-2019-7711",
            "CVE-2019-9974",
            "CVE-2019-6335",
            "CVE-2019-1787",
            "CVE-2019-8748",
            "CVE-2019-9368",
            "CVE-2019-7940",
            "CVE-2019-18769",
            "CVE-2019-1728",
            "CVE-2019-11213",
            "CVE-2019-16792",
            "CVE-2019-16205",
            "CVE-2019-8029",
            "CVE-2019-17342",
            "CVE-2019-9792",
            "CVE-2019-4139",
            "CVE-2019-17399",
            "CVE-2019-6273",
            "CVE-2019-7974",
            "CVE-2019-10956",
            "CVE-2019-11163",
            "CVE-2019-15064",
            "CVE-2019-2239",
            "CVE-2019-5579",
            "CVE-2019-20091",
            "CVE-2019-4860",
            "CVE-2019-0186",
            "CVE-2019-2257",
            "CVE-2019-16320",
            "CVE-2019-9147",
            "CVE-2019-5084",
            "CVE-2019-0887",
            "CVE-2019-0819",
            "CVE-2019-1959",
            "CVE-2019-3735"
        ]
    },
    "HelloWorld": {
        "Scan": {
            "entities": [
                {
                    "entity-id": "40d6a1cb-9b32-4a93-a0d9-f3eec2e225cb",
                    "ip_address": "37.201.236.182",
                    "type": "Router",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-4860",
                        "CVE-2019-19817",
                        "CVE-2019-0819",
                        "CVE-2019-8654"
                    ]
                },
                {
                    "entity-id": "f67541a0-d7fe-44d2-8734-b1734ae4e1ab",
                    "ip_address": "175.190.247.180",
                    "type": "Printer",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-7974",
                        "CVE-2019-1003074",
                        "CVE-2019-20091"
                    ]
                },
                {
                    "entity-id": "3ad97b0a-5d91-4dad-b979-e08d3a2d499d",
                    "ip_address": "194.17.62.219",
                    "type": "Printer",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-0746"
                    ]
                },
                {
                    "entity-id": "d75c234f-d7e9-464b-ae05-f28e720f8b12",
                    "ip_address": "71.122.181.11",
                    "type": "HSM",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-7169",
                        "CVE-2019-6291",
                        "CVE-2019-6335",
                        "CVE-2019-9322",
                        "CVE-2019-17426"
                    ]
                },
                {
                    "entity-id": "dcc26c08-b40f-4793-bf85-4c54b64e4e5d",
                    "ip_address": "136.144.93.38",
                    "type": "Endpoint",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-14805",
                        "CVE-2019-18769"
                    ]
                },
                {
                    "entity-id": "59e9c5e0-5c0c-493f-8314-ac92318a1462",
                    "ip_address": "136.181.109.109",
                    "type": "Endpoint",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-10479",
                        "CVE-2019-13524",
                        "CVE-2019-9580",
                        "CVE-2019-0240",
                        "CVE-2019-6457"
                    ]
                },
                {
                    "entity-id": "f403b41b-587e-4293-a802-0bc5ba03a3f2",
                    "ip_address": "159.105.212.108",
                    "type": "Train",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-19592",
                        "CVE-2019-10490",
                        "CVE-2019-0757",
                        "CVE-2019-15485"
                    ]
                },
                {
                    "entity-id": "6ed7469a-5158-47a5-b17f-8fb721e51227",
                    "ip_address": "5.114.109.222",
                    "type": "HSM",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-9375",
                        "CVE-2019-18671",
                        "CVE-2019-13301",
                        "CVE-2019-16205",
                        "CVE-2019-8994"
                    ]
                },
                {
                    "entity-id": "ab35bd99-44f9-4096-a9ae-adca874f90e2",
                    "ip_address": "172.60.9.133",
                    "type": "Train",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-0734",
                        "CVE-2019-16177",
                        "CVE-2019-10763",
                        "CVE-2019-18241",
                        "CVE-2019-15472"
                    ]
                },
                {
                    "entity-id": "9500171c-1d82-4df0-9e55-8211925a7366",
                    "ip_address": "111.30.110.70",
                    "type": "Fridge",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-11163"
                    ]
                },
                {
                    "entity-id": "795ca8b4-32ad-4ba9-b578-7ac7e35b2a81",
                    "ip_address": "97.213.154.249",
                    "type": "Gate",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-7940",
                        "CVE-2019-2257"
                    ]
                },
                {
                    "entity-id": "7cf5d465-c9e1-48ca-b952-3d287cce5aba",
                    "ip_address": "127.96.3.67",
                    "type": "Fan",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-5084",
                        "CVE-2019-0667",
                        "CVE-2019-15497",
                        "CVE-2019-0887"
                    ]
                },
                {
                    "entity-id": "8d425bf0-e3e8-49fd-89e1-e918d3e1f9f4",
                    "ip_address": "209.109.7.246",
                    "type": "Gate",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-9792",
                        "CVE-2019-18250",
                        "CVE-2019-17399",
                        "CVE-2019-12978"
                    ]
                },
                {
                    "entity-id": "c80278a6-70af-40a9-9914-535f9efba725",
                    "ip_address": "135.209.178.232",
                    "type": "Gate",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-8029"
                    ]
                },
                {
                    "entity-id": "2d926b20-6b7d-4a3d-85c7-3edded7ef5a7",
                    "ip_address": "203.69.245.105",
                    "type": "HSM",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-1732"
                    ]
                },
                {
                    "entity-id": "3e7b9099-b86d-43b8-897e-84dbabb2e656",
                    "ip_address": "131.97.249.220",
                    "type": "Fridge",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-12762",
                        "CVE-2019-13507",
                        "CVE-2019-16792",
                        "CVE-2019-10492"
                    ]
                },
                {
                    "entity-id": "ef31a797-f340-4421-96ae-966d880463f6",
                    "ip_address": "5.115.147.13",
                    "type": "IoT Device",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-9974",
                        "CVE-2019-10956",
                        "CVE-2019-8748"
                    ]
                },
                {
                    "entity-id": "4c5ce6a4-be8c-4341-b09c-075f2285c18e",
                    "ip_address": "77.178.129.200",
                    "type": "Fridge",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-13100",
                        "CVE-2019-20443",
                        "CVE-2019-10528"
                    ]
                },
                {
                    "entity-id": "70fe2247-50e6-463b-8f65-bea4916cac67",
                    "ip_address": "159.58.108.231",
                    "type": "Train",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-15233"
                    ]
                },
                {
                    "entity-id": "fa8fcd0c-6862-46d7-b649-488c56509822",
                    "ip_address": "172.71.119.38",
                    "type": "Train",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-12611",
                        "CVE-2019-14357",
                        "CVE-2019-5579",
                        "CVE-2019-20424"
                    ]
                },
                {
                    "entity-id": "9ca55748-cba2-469c-a468-73666f5a182a",
                    "ip_address": "137.39.150.42",
                    "type": "Mainframe",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-5632",
                        "CVE-2019-9025"
                    ]
                },
                {
                    "entity-id": "8fef9722-d627-4737-81b9-f1454032b640",
                    "ip_address": "254.143.245.36",
                    "type": "Train",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-19532",
                        "CVE-2019-10311",
                        "CVE-2019-9578"
                    ]
                },
                {
                    "entity-id": "146685d1-9899-425d-b2f0-fa082fbab0a9",
                    "ip_address": "132.172.112.36",
                    "type": "Train",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-7711",
                        "CVE-2019-10481",
                        "CVE-2019-1959"
                    ]
                },
                {
                    "entity-id": "b0a94cfd-574d-468f-8f82-10dc3fe00ff8",
                    "ip_address": "139.166.107.214",
                    "type": "IoT Device",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-11331"
                    ]
                },
                {
                    "entity-id": "bb76f8cf-d264-42ce-bf47-c61da8324a43",
                    "ip_address": "45.174.165.64",
                    "type": "Printer",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-5095",
                        "CVE-2019-2658",
                        "CVE-2019-15593",
                        "CVE-2019-16320",
                        "CVE-2019-11213"
                    ]
                },
                {
                    "entity-id": "ec6ad2df-37ce-4eed-ba3e-1507ff7d975a",
                    "ip_address": "99.120.52.25",
                    "type": "Router",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-5114",
                        "CVE-2019-9147"
                    ]
                },
                {
                    "entity-id": "85273e98-e070-42e0-9b4e-3cefa15fffac",
                    "ip_address": "254.186.92.211",
                    "type": "IoT Device",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-17342",
                        "CVE-2019-17269",
                        "CVE-2019-6273",
                        "CVE-2019-5880",
                        "CVE-2019-9368"
                    ]
                },
                {
                    "entity-id": "05b53757-7155-4a5f-b047-b968e6ca2dec",
                    "ip_address": "119.78.96.64",
                    "type": "Router",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-16237"
                    ]
                },
                {
                    "entity-id": "ec8e0a9b-9321-4bc0-9247-c10808686fa8",
                    "ip_address": "81.119.103.180",
                    "type": "Server",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-5252",
                        "CVE-2019-1512"
                    ]
                },
                {
                    "entity-id": "4f3121a8-de72-42ad-b490-10b307e0c553",
                    "ip_address": "201.145.25.59",
                    "type": "Train",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-1728",
                        "CVE-2019-2946"
                    ]
                },
                {
                    "entity-id": "df439f01-59b2-4fc7-9356-a845534158e2",
                    "ip_address": "108.94.125.170",
                    "type": "Endpoint",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-15064",
                        "CVE-2019-19767",
                        "CVE-2019-2239",
                        "CVE-2019-2923"
                    ]
                },
                {
                    "entity-id": "5082677b-eb00-4724-b2d6-f64010a85e60",
                    "ip_address": "162.183.92.207",
                    "type": "HSM",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-16534",
                        "CVE-2019-5250",
                        "CVE-2019-11632",
                        "CVE-2019-11971",
                        "CVE-2019-4811"
                    ]
                },
                {
                    "entity-id": "a10f4a77-45ea-4213-979a-3031835d75f6",
                    "ip_address": "77.165.85.252",
                    "type": "Fan",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-1716",
                        "CVE-2019-10401",
                        "CVE-2019-0335"
                    ]
                },
                {
                    "entity-id": "636e3504-5a6b-404c-96e2-c5bd9524a4d5",
                    "ip_address": "145.132.60.210",
                    "type": "HSM",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-3420",
                        "CVE-2019-5763",
                        "CVE-2019-0200",
                        "CVE-2019-5989",
                        "CVE-2019-12162"
                    ]
                },
                {
                    "entity-id": "6851f735-5d3b-434a-978e-97536317def7",
                    "ip_address": "153.44.130.204",
                    "type": "IoT Device",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-13339",
                        "CVE-2019-4038",
                        "CVE-2019-4856"
                    ]
                },
                {
                    "entity-id": "56936e07-bc42-48cb-9aa8-2aa6c4b22ddc",
                    "ip_address": "191.18.113.68",
                    "type": "IoT Device",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-8139",
                        "CVE-2019-5450"
                    ]
                },
                {
                    "entity-id": "a2fbc2d1-e76e-4245-b9c2-74c12e1d4d38",
                    "ip_address": "180.247.251.51",
                    "type": "Endpoint",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-3735",
                        "CVE-2019-5789",
                        "CVE-2019-2128",
                        "CVE-2019-5279"
                    ]
                },
                {
                    "entity-id": "e1383013-9086-433b-a8a7-8b67b221b082",
                    "ip_address": "217.31.78.215",
                    "type": "Smart Beer",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-2889",
                        "CVE-2019-9114"
                    ]
                },
                {
                    "entity-id": "e961ac9c-b0f2-49ec-8193-7a1ae8e3f038",
                    "ip_address": "43.219.254.133",
                    "type": "IoT Device",
                    "vulnerability_status": "SERIOUS",
                    "vulns": [
                        "CVE-2019-9624",
                        "CVE-2019-0186"
                    ]
                },
                {
                    "entity-id": "88e31eb7-49b7-4870-bb17-d31a290ecadb",
                    "ip_address": "74.155.134.147",
                    "type": "HSM",
                    "vulnerability_status": "TRIVIAL",
                    "vulns": [
                        "CVE-2019-4139",
                        "CVE-2019-7081",
                        "CVE-2019-1787",
                        "CVE-2019-18824"
                    ]
                },
                {
                    "entity-id": "12ce3171-49f1-4ee6-ac94-ef2c141f23ed",
                    "ip_address": "188.186.34.143",
                    "type": "Endpoint",
                    "vulnerability_status": "NON-SERIOUS",
                    "vulns": [
                        "CVE-2019-8926",
                        "CVE-2019-6579",
                        "CVE-2019-7390",
                        "CVE-2019-2610"
                    ]
                }
            ],
            "scan_id": "100",
            "status": "COMPLETE"
        }
    }
}
```

#### Human Readable Output

>### Scan 100 results
>|entity-id|ip_address|type|vulnerability_status|vulns|
>|---|---|---|---|---|
>| 40d6a1cb-9b32-4a93-a0d9-f3eec2e225cb | 37.201.236.182 | Router | NON-SERIOUS | CVE-2019-4860,<br/>CVE-2019-19817,<br/>CVE-2019-0819,<br/>CVE-2019-8654 |
>| f67541a0-d7fe-44d2-8734-b1734ae4e1ab | 175.190.247.180 | Printer | SERIOUS | CVE-2019-7974,<br/>CVE-2019-1003074,<br/>CVE-2019-20091 |
>| 3ad97b0a-5d91-4dad-b979-e08d3a2d499d | 194.17.62.219 | Printer | NON-SERIOUS | CVE-2019-0746 |
>| d75c234f-d7e9-464b-ae05-f28e720f8b12 | 71.122.181.11 | HSM | NON-SERIOUS | CVE-2019-7169,<br/>CVE-2019-6291,<br/>CVE-2019-6335,<br/>CVE-2019-9322,<br/>CVE-2019-17426 |
>| dcc26c08-b40f-4793-bf85-4c54b64e4e5d | 136.144.93.38 | Endpoint | TRIVIAL | CVE-2019-14805,<br/>CVE-2019-18769 |
>| 59e9c5e0-5c0c-493f-8314-ac92318a1462 | 136.181.109.109 | Endpoint | NON-SERIOUS | CVE-2019-10479,<br/>CVE-2019-13524,<br/>CVE-2019-9580,<br/>CVE-2019-0240,<br/>CVE-2019-6457 |
>| f403b41b-587e-4293-a802-0bc5ba03a3f2 | 159.105.212.108 | Train | TRIVIAL | CVE-2019-19592,<br/>CVE-2019-10490,<br/>CVE-2019-0757,<br/>CVE-2019-15485 |
>| 6ed7469a-5158-47a5-b17f-8fb721e51227 | 5.114.109.222 | HSM | NON-SERIOUS | CVE-2019-9375,<br/>CVE-2019-18671,<br/>CVE-2019-13301,<br/>CVE-2019-16205,<br/>CVE-2019-8994 |
>| ab35bd99-44f9-4096-a9ae-adca874f90e2 | 172.60.9.133 | Train | SERIOUS | CVE-2019-0734,<br/>CVE-2019-16177,<br/>CVE-2019-10763,<br/>CVE-2019-18241,<br/>CVE-2019-15472 |
>| 9500171c-1d82-4df0-9e55-8211925a7366 | 111.30.110.70 | Fridge | SERIOUS | CVE-2019-11163 |
>| 795ca8b4-32ad-4ba9-b578-7ac7e35b2a81 | 97.213.154.249 | Gate | SERIOUS | CVE-2019-7940,<br/>CVE-2019-2257 |
>| 7cf5d465-c9e1-48ca-b952-3d287cce5aba | 127.96.3.67 | Fan | NON-SERIOUS | CVE-2019-5084,<br/>CVE-2019-0667,<br/>CVE-2019-15497,<br/>CVE-2019-0887 |
>| 8d425bf0-e3e8-49fd-89e1-e918d3e1f9f4 | 209.109.7.246 | Gate | SERIOUS | CVE-2019-9792,<br/>CVE-2019-18250,<br/>CVE-2019-17399,<br/>CVE-2019-12978 |
>| c80278a6-70af-40a9-9914-535f9efba725 | 135.209.178.232 | Gate | TRIVIAL | CVE-2019-8029 |
>| 2d926b20-6b7d-4a3d-85c7-3edded7ef5a7 | 203.69.245.105 | HSM | NON-SERIOUS | CVE-2019-1732 |
>| 3e7b9099-b86d-43b8-897e-84dbabb2e656 | 131.97.249.220 | Fridge | NON-SERIOUS | CVE-2019-12762,<br/>CVE-2019-13507,<br/>CVE-2019-16792,<br/>CVE-2019-10492 |
>| ef31a797-f340-4421-96ae-966d880463f6 | 5.115.147.13 | IoT Device | TRIVIAL | CVE-2019-9974,<br/>CVE-2019-10956,<br/>CVE-2019-8748 |
>| 4c5ce6a4-be8c-4341-b09c-075f2285c18e | 77.178.129.200 | Fridge | TRIVIAL | CVE-2019-13100,<br/>CVE-2019-20443,<br/>CVE-2019-10528 |
>| 70fe2247-50e6-463b-8f65-bea4916cac67 | 159.58.108.231 | Train | TRIVIAL | CVE-2019-15233 |
>| fa8fcd0c-6862-46d7-b649-488c56509822 | 172.71.119.38 | Train | SERIOUS | CVE-2019-12611,<br/>CVE-2019-14357,<br/>CVE-2019-5579,<br/>CVE-2019-20424 |
>| 9ca55748-cba2-469c-a468-73666f5a182a | 137.39.150.42 | Mainframe | TRIVIAL | CVE-2019-5632,<br/>CVE-2019-9025 |
>| 8fef9722-d627-4737-81b9-f1454032b640 | 254.143.245.36 | Train | NON-SERIOUS | CVE-2019-19532,<br/>CVE-2019-10311,<br/>CVE-2019-9578 |
>| 146685d1-9899-425d-b2f0-fa082fbab0a9 | 132.172.112.36 | Train | TRIVIAL | CVE-2019-7711,<br/>CVE-2019-10481,<br/>CVE-2019-1959 |
>| b0a94cfd-574d-468f-8f82-10dc3fe00ff8 | 139.166.107.214 | IoT Device | TRIVIAL | CVE-2019-11331 |
>| bb76f8cf-d264-42ce-bf47-c61da8324a43 | 45.174.165.64 | Printer | SERIOUS | CVE-2019-5095,<br/>CVE-2019-2658,<br/>CVE-2019-15593,<br/>CVE-2019-16320,<br/>CVE-2019-11213 |
>| ec6ad2df-37ce-4eed-ba3e-1507ff7d975a | 99.120.52.25 | Router | NON-SERIOUS | CVE-2019-5114,<br/>CVE-2019-9147 |
>| 85273e98-e070-42e0-9b4e-3cefa15fffac | 254.186.92.211 | IoT Device | TRIVIAL | CVE-2019-17342,<br/>CVE-2019-17269,<br/>CVE-2019-6273,<br/>CVE-2019-5880,<br/>CVE-2019-9368 |
>| 05b53757-7155-4a5f-b047-b968e6ca2dec | 119.78.96.64 | Router | SERIOUS | CVE-2019-16237 |
>| ec8e0a9b-9321-4bc0-9247-c10808686fa8 | 81.119.103.180 | Server | TRIVIAL | CVE-2019-5252,<br/>CVE-2019-1512 |
>| 4f3121a8-de72-42ad-b490-10b307e0c553 | 201.145.25.59 | Train | TRIVIAL | CVE-2019-1728,<br/>CVE-2019-2946 |
>| df439f01-59b2-4fc7-9356-a845534158e2 | 108.94.125.170 | Endpoint | NON-SERIOUS | CVE-2019-15064,<br/>CVE-2019-19767,<br/>CVE-2019-2239,<br/>CVE-2019-2923 |
>| 5082677b-eb00-4724-b2d6-f64010a85e60 | 162.183.92.207 | HSM | NON-SERIOUS | CVE-2019-16534,<br/>CVE-2019-5250,<br/>CVE-2019-11632,<br/>CVE-2019-11971,<br/>CVE-2019-4811 |
>| a10f4a77-45ea-4213-979a-3031835d75f6 | 77.165.85.252 | Fan | SERIOUS | CVE-2019-1716,<br/>CVE-2019-10401,<br/>CVE-2019-0335 |
>| 636e3504-5a6b-404c-96e2-c5bd9524a4d5 | 145.132.60.210 | HSM | SERIOUS | CVE-2019-3420,<br/>CVE-2019-5763,<br/>CVE-2019-0200,<br/>CVE-2019-5989,<br/>CVE-2019-12162 |
>| 6851f735-5d3b-434a-978e-97536317def7 | 153.44.130.204 | IoT Device | SERIOUS | CVE-2019-13339,<br/>CVE-2019-4038,<br/>CVE-2019-4856 |
>| 56936e07-bc42-48cb-9aa8-2aa6c4b22ddc | 191.18.113.68 | IoT Device | TRIVIAL | CVE-2019-8139,<br/>CVE-2019-5450 |
>| a2fbc2d1-e76e-4245-b9c2-74c12e1d4d38 | 180.247.251.51 | Endpoint | TRIVIAL | CVE-2019-3735,<br/>CVE-2019-5789,<br/>CVE-2019-2128,<br/>CVE-2019-5279 |
>| e1383013-9086-433b-a8a7-8b67b221b082 | 217.31.78.215 | Smart Beer | TRIVIAL | CVE-2019-2889,<br/>CVE-2019-9114 |
>| e961ac9c-b0f2-49ec-8193-7a1ae8e3f038 | 43.219.254.133 | IoT Device | SERIOUS | CVE-2019-9624,<br/>CVE-2019-0186 |
>| 88e31eb7-49b7-4870-bb17-d31a290ecadb | 74.155.134.147 | HSM | TRIVIAL | CVE-2019-4139,<br/>CVE-2019-7081,<br/>CVE-2019-1787,<br/>CVE-2019-18824 |
>| 12ce3171-49f1-4ee6-ac94-ef2c141f23ed | 188.186.34.143 | Endpoint | NON-SERIOUS | CVE-2019-8926,<br/>CVE-2019-6579,<br/>CVE-2019-7390,<br/>CVE-2019-2610 |

