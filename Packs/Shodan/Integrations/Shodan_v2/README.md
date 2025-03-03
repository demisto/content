Shodan is a search engine for Internet-connected devices. Unlike traditional search engines that index websites, Shodan indexes information about the devices connected to the internet, such as servers, routers, webcams, and other IoT devices.

## Configure Shodan v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key |  | False |
| Base URL to Shodan API |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| The maximum number of events per fetch |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### search

***
Searches Shodan using facets to get summary information on properties.


#### Base Command

`search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query for searching the database of banners. The search query supports filtering using the "filter:value" format to narrow your search. For example, the query "apache country:DE" returns Apache web servers located in Germany. | Required |
| facets | A CSV list of properties on which to get summary information. The search query supports filtering using the "property:count" format to define the number of facets to return for a property. For example, the query "country:100" returns the top 100 countries. | Optional |
| page | The page number of the fetched results. Each page contains a maximum of 100 results. Default is 1. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Banner.Org | String | The name of the organization to which the space of the IP address space for the searched device is assigned. |
| Shodan.Banner.Isp | String | The Internet Service Provider that provides the organization with the IP address space for the searched device. |
| Shodan.Banner.Transport | String | The IP address transport protocol used to fetch the summary information. Can be "UDP" or "TCP". |
| Shodan.Banner.Asn | String | The Autonomous System Number. For example, "AS4837". |
| Shodan.Banner.IP | String | The IP address of the host as a string. |
| Shodan.Banner.Port | Number | The port number on which the service is operating. |
| Shodan.Banner.Ssl.versions | String | The list of SSL versions that are supported by the server. Unsupported versions are prefixed with a "-". For example, \["TLSv1", "-SSLv2"\] means that the server supports TLSv1, but does not support SSLv2. |
| Shodan.Banner.Hostnames | String | An array of strings containing all of the host names that have been assigned to the IP address for the searched device. |
| Shodan.Banner.Location.City | String | The city in which the searched device is located. |
| Shodan.Banner.Location.Longitude | Number | The longitude of the geolocation of the searched device. |
| Shodan.Banner.Location.Latitude | Number | The latitude of the geolocation of the searched device. |
| Shodan.Banner.Location.Country | String | The country in which the searched device is located. |
| Shodan.Banner.Timestamp | Date | The timestamp in UTC format indicating when the banner was fetched from the searched device. |
| Shodan.Banner.Domains | String | An array of strings containing the top-level domains for the host names of the searched device. It is a utility property for filtering by a top-level domain instead of a subdomain. It supports handling global top-level domains that have several dots in the domain. For example, "co.uk". |
| Shodan.Banner.OS | String | The operating system that powers the searched device. |


#### Command Example

```!search query="country:HK org:RLL-HK -port:80 -port:443 -port:21 -port:25 has_ssl:false" using-brand=Shodan_v2```

#### Context Example

```json
{
    "Shodan": [
        {
            "Banner": {
                "Asn": "AS9311",
                "Domains": [],
                "Hostnames": [],
                "IP": "1.2.3.4",
                "Isp": "HITRON TECHNOLOGY INC.",
                "Location": {
                    "City": "Hong Kong",
                    "Country": "Hong Kong",
                    "Latitude": 22.27832,
                    "Longitude": 114.17469
                },
                "OS": null,
                "Org": "RLL-HK",
                "Port": 5353,
                "Ssl": {
                    "versions": []
                },
                "Timestamp": "2021-08-17T03:33:07.392394",
                "Transport": "udp"
            }
        },
        {
            "Banner": {
                "Asn": "AS9919",
                "Domains": [],
                "Hostnames": [],
                "IP": "1.2.3.4",
                "Isp": "New Century InfoComm Tech Co., Ltd.",
                "Location": {
                    "City": "Hong Kong",
                    "Country": "Hong Kong",
                    "Latitude": 22.27832,
                    "Longitude": 114.17469
                },
                "OS": null,
                "Org": "RLL-HK",
                "Port": 5353,
                "Ssl": {
                    "versions": []
                },
                "Timestamp": "2021-08-17T03:21:00.992437",
                "Transport": "udp"
            }
        },
        {
            "Banner": {
                "Asn": "AS9311",
                "Domains": [],
                "Hostnames": [],
                "IP": "1.2.3.4",
                "Isp": "HITRON TECHNOLOGY INC.",
                "Location": {
                    "City": "Hong Kong",
                    "Country": "Hong Kong",
                    "Latitude": 22.27832,
                    "Longitude": 114.17469
                },
                "OS": null,
                "Org": "RLL-HK",
                "Port": 5353,
                "Ssl": {
                    "versions": []
                },
                "Timestamp": "2021-08-17T03:13:54.617598",
                "Transport": "udp"
            }
        }
    ]
}
```

#### Human Readable Output

>Search results for query "country:HK org:RLL-HK -port:80 -port:443 -port:21 -port:25 has_ssl:false" - page 1, facets: None
>|IP|Port|Timestamp|
>|---|---|---|
>| 1.2.3.4 | 5353 | 2021-08-17T03:13:54.617598 |


### ip

***
Returns all services that have been found on the IP address of the searched host.


#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP address of the host. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.ASN | Unknown | The Autonomous System Number. |
| IP.Address | Unknown | The IP address. |
| IP.Geo.Country | Unknown | The country of a given IP address. |
| IP.Geo.Description | Unknown | The description of the location. |
| IP.Geo.Location | Unknown | The latitude and longitude of an IP address. |
| IP.Hostname | Unknown | The hostname of the IP address. |
| IP.Relationships | Unknown | The relationships between the ip and it's CVEs. |
| Shodan.IP.Tags | String | The tags associated with the IP address. |
| Shodan.IP.Latitude | Number | The latitude of the geolocation of the searched device. |
| Shodan.IP.Org | String | The name of the organization to which the IP space for the searched device is assigned. |
| Shodan.IP.ASN | String | The Autonomous System Number. For example, "AS4837". |
| Shodan.IP.ISP | String | The Internet Service Provider that provides the organization with the IP space for the searched device. |
| Shodan.IP.Longitude | Number | The longitude of the geolocation of the searched device. |
| Shodan.IP.LastUpdate | Date | The timestamp in UTC format indicating when the banner was fetched from the searched device. |
| Shodan.IP.CountryName | String | The country in which the searched device is located. |
| Shodan.IP.OS | String | The operating system on which the searched device is running. |
| Shodan.IP.Port | Number | The port number on which the service is operating. |
| Shodan.IP.Address | String | The IP address of the host as a string. |
| Shodan.IP.Vulnerabilities | Unknown | A list of Vulnerabilities. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |

#### Command Example

```!ip ip="8.8.8.8" using-brand="Shodan_v2"```

#### Context Example

```json
{
    "IP": {
        "ASN": "AS15169",
        "Address": "8.8.8.8",
        "Geo": {
            "Country": "United States",
            "Location": "37.406,-122.078"
        },
        "Hostname": "dns.google",
        "Relationships": [
          {
            "EntityA": "8.8.8.8",
            "EntityAType": "IP",
            "EntityB": "CVE-2016-11111",
            "EntityBType": "CVE",
            "Relationship": "related-to"
          }
        ]
    },
    "Shodan": {
        "IP": {
            "ASN": "AS15169",
            "Address": "8.8.8.8",
            "CountryName": "United States",
            "ISP": "Google LLC",
            "LastUpdate": "2021-08-20T17:13:07.423800",
            "Latitude": 37.4056,
            "Longitude": -122.0775,
            "OS": null,
            "Org": "Google LLC",
            "Port": [
                53
            ],
            "Tag": [],
            "Vulnerabilities": ["CVE-2016-11111"]
        }
    },
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip",
        "Vendor": "Shodan_v2"
    }
}
```

#### Human Readable Output

>Shodan details for IP 8.8.8.8
>|ASN|Country|Hostname|ISP|Location|Ports|
>|---|---|---|---|---|---|
>| AS15169 | United States | dns.google | Google LLC | 37.406,-122.078 | 53 |


### shodan-search-count

***
Returns the total number of results that match only the specified query or facet settings. This command does not return host results. This command does not consume query credits.


#### Base Command

`shodan-search-count`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query for searching the database of banners. The search query supports filtering using the "filter:value" format to narrow your search. For example, the query "apache country:DE" returns Apache web servers located in Germany. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Search.ResultCount | Number | The number of results matched in the search query. |


#### Command Example

```!shodan-search-count query="country:HK product:Apache"```

#### Context Example

```json
{
    "Shodan": {
        "Search": {
            "ResultCount": 498645
        }
    }
}
```

#### Human Readable Output

>498645 results for query "country:HK product:Apache"

### shodan-scan-ip

***
Requests Shodan to crawl a network.


#### Base Command

`shodan-scan-ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ips | A CSV list of IP addresses or netblocks for Shodan to crawl defined in CIDR notation. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Scan.ID | String | The unique ID of the scan. |
| Shodan.Scan.Status | String | The status of the scan. |


#### Command Example

```!shodan-scan-ip ips=8.8.8.8```

#### Context Example

```json
{
    "Shodan": {
        "Scan": {
            "ID": "wQEp0bIIEHklpAwa",
            "Status": "PROCESSING"
        }
    }
}
```

#### Human Readable Output

>Scanning results for scan wQEp0bIIEHklpAwa
>|ID|Status|
>|---|---|
>| wQEp0bIIEHklpAwa | PROCESSING |


### shodan-scan-internet

***
Requests for Shodan to perform a scan on the specified port and protocol.


#### Base Command

`shodan-scan-internet`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| port | The port for which Shodan crawls the Internet. | Required |
| protocol | The name of the protocol used to interrogate the port. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Scan.ID | String | The ID of the initial scan. |


#### Command Example

``` ```

#### Human Readable Output



### shodan-scan-status

***
Checks the progress of a previously submitted scan request on the specified port and protocol.


#### Base Command

`shodan-scan-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanID | The unique ID of the initial scan. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Scan.Id | String | The unique ID of the scan request checked for progress. |
| Shodan.Scan.Status | String | The status of the scan job checked for progress. |


#### Command Example

```!shodan-scan-status scanID=7rbp1CAtx91BMwcg```

#### Context Example

```json
{
    "Shodan": {
        "Scan": {
            "ID": "7rbp1CAtx91BMwcg",
            "Status": "DONE"
        }
    }
}
```

#### Human Readable Output

>Scanning results for scan 7rbp1CAtx91BMwcg
>|ID|Status|
>|---|---|
>| 7rbp1CAtx91BMwcg | DONE |


### shodan-create-network-alert

***
Creates a network alert for a defined IP address or netblock used for subscribing to changes or events that are discovered within the netblock's range.


#### Base Command

`shodan-create-network-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertName | The name of the network alert. | Required |
| ip | A list of IP addresses or network ranges defined in CIDR notation. | Required |
| expires | The number of seconds for the network alert to remain active. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Alert.ID | String | The ID of the subscription of the specified network alert. |
| Shodan.Alert.Expires | String | The number of seconds that the specified network alert remains active. |


#### Command Example

```!shodan-create-network-alert alertName="test_alert" ip="1.1.1.1"```

#### Context Example

```json
{
    "Shodan": {
        "Alert": {
            "Expires": 0,
            "ID": "CB68M776ICCMS36L"
        }
    }
}
```

#### Human Readable Output

>Alert ID CB68M776ICCMS36L
>|Expires|IP|Name|
>|---|---|---|
>| 0 | 1.1.1.1 | test_alert |


### shodan-network-get-alert-by-id

***
Gets the details of a network alert.


#### Base Command

`shodan-network-get-alert-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | The ID of the network alert. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Alert.ID | String | The ID of the subscription of the network alert. |
| Shodan.Alert.Expires | String | The number of seconds that the network alert remains active. |


#### Command Example

```!shodan-network-get-alert-by-id alertID="0EKRH38BBQEHTQ3E"```

#### Context Example

```json
{
    "Shodan": {
        "Alert": {
            "Expires": 0,
            "ID": "0EKRH38BBQEHTQ3E"
        }
    }
}
```

#### Human Readable Output

>Alert ID 0EKRH38BBQEHTQ3E
>|Expires|IP|Name|
>|---|---|---|
>| 0 | 1.2.3.4 | test_alert |


### shodan-network-get-alerts

***
Gets a list of all created network alerts.


#### Base Command

`shodan-network-get-alerts`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Shodan.Alert.ID | String | The IDs of the subscriptions of the network alerts. |
| Shodan.Alert.Expires | String | The number of seconds that the network alerts remain active. |


#### Command Example

```!shodan-network-get-alerts```

#### Context Example

```json
{
    "Shodan": [
        {
            "Alert": {
                "Expires": 0,
                "ID": "0EKRH38BBQEHTQ3E"
            }
        },
        {
            "Alert": {
                "Expires": 0,
                "ID": "CB68M776ICCMS36L"
            }
        },
        {
            "Alert": {
                "Expires": 0,
                "ID": "HTWLPTVPUHN5VAGA"
            }
        },
        {
            "Alert": {
                "Expires": 0,
                "ID": "VXGB6CZ536X5AWE6"
            }
        }
    ]
}
```

#### Human Readable Output

>Alert ID VXGB6CZ536X5AWE6
>|Expires|IP|Name|
>|---|---|---|
>| 0 | 1.1.1.1 | test_alert |


### shodan-network-delete-alert

***
Removes the specified network alert.


#### Base Command

`shodan-network-delete-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | The ID of the network alert to remove. | Required |


#### Context Output

There is no context output for this command.

#### Command Example

```!shodan-network-delete-alert alertID="0EKRH38BBQEHTQ3E"```

#### Human Readable Output

>Deleted alert 0EKRH38BBQEHTQ3E

### shodan-network-alert-set-trigger

***
Enables receiving notifications for network alerts that are set off by the specified triggers.


#### Base Command

`shodan-network-alert-set-trigger`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | The ID of the network alert for which to enable notifications. | Required |
| Trigger | The name of the trigger. | Required |


#### Context Output

There is no context output for this command.

#### Command Example

```!shodan-network-alert-set-trigger alertID="0EKRH38BBQEHTQ3E" Trigger=any```

#### Human Readable Output

>Set trigger "any" for alert 0EKRH38BBQEHTQ3E

### shodan-network-alert-remove-trigger

***
Disables receiving notifications for network alerts that are set off by the specified triggers.


#### Base Command

`shodan-network-alert-remove-trigger`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | The ID of the network alert for which to disable notifications. | Required |
| Trigger | The name of the trigger. | Required |


#### Context Output

There is no context output for this command.

#### Command Example

```!shodan-network-alert-remove-trigger alertID="0EKRH38BBQEHTQ3E" Trigger="any"```

#### Human Readable Output

>Deleted trigger "any" for alert 0EKRH38BBQEHTQ3E

### shodan-network-alert-whitelist-service

***
Ignores the specified services for network alerts that are set off by the specified triggers.


#### Base Command

`shodan-network-alert-whitelist-service`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | The ID of the network alert for which to ignore the specified services. | Required |
| trigger | The name of the trigger. | Required |
| service | The service specified in the "ip:port" format. For example, "1.1.1.1:80". | Required |


#### Context Output

There is no context output for this command.

#### Command Example

```!shodan-network-alert-whitelist-service alertID="0EKRH38BBQEHTQ3E" trigger="any" service="1.1.1.1:80"```

#### Human Readable Output

>Whitelisted service "1.1.1.1:80" for trigger any in alert 0EKRH38BBQEHTQ3E

### shodan-network-alert-remove-service-from-whitelist

***
Resumes receiving notifications for network alerts that are set off by the specified triggers.


#### Base Command

`shodan-network-alert-remove-service-from-whitelist`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertID | The ID of the alert for which to resume the specified services. | Required |
| trigger | The name of the trigger. | Required |
| service | The service specified in the "ip:port" format. For example, "1.1.1.1:80". | Required |


#### Context Output

There is no context output for this command.

#### Command Example

```!shodan-network-alert-remove-service-from-whitelist alertID="0EKRH38BBQEHTQ3E" trigger="any" service="1.1.1.1:80"```

#### Human Readable Output

>Removed service "1.1.1.1:80" for trigger any in alert 0EKRH38BBQEHTQ3E from the allow list
### shodan-get-events

***
Retrieves events from Shodan.

#### Base Command

`shodan-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If set to 'True', the command will create events; otherwise, it will only display them. Possible values are: True, False. Default is False. | Optional | 
| start_date | Fetch events created after this date. You can also use relative terms like "3 days ago". Default is 3 days ago. | Optional | 
| max_fetch | The maximum amount of events to return. Default is 50000. | Optional | 

#### Context Output

There is no context output for this command.


## Fetch Events

Fetch process returns a listing of all the network alerts that are currently active on the account.

To enable the Shodan integration you need to have an API key, which you can get for free by creating a Shodan account <https://account.shodan.io/register>
Once you have an API key, you insert it into the *API Key* field and click the **Test** button.


## Rate Limits

All API plans are subject to a rate limit of 1 request per second - [docs](https://account.shodan.io/billing)
