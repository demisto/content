Returns DNS details for a domain

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 5.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| domain | The domain to query |
| server | IP of the DNS Server to use \(default: system settings\) |
| use_tcp | Use TCP for the query \(default: False\) |
| qtype | Comma separated list of query types \(default: CNAME,NS,A,AAAA\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DomainDNSDetails.A | Domain A records. | String |
| DomainDNSDetails.AAAA | Domain AAAA records. | String |
| DomainDNSDetails.CNAME | Domain CNAME records. | String |
| DomainDNSDetails.NS | Domain NS records. | String |
| DomainDNSDetails.domain | Domain name used in the query. | String |
| DomainDNSDetails.server | Name server that returned the result. | String |


## Script Example
```!GetDomainDNSDetails domain=example.com```

## Context Example
```json
{
    "DomainDNSDetails": {
        "A": [
            "10.11.12.13"
        ],
        "AAAA": [
            "2001:2001:200:1:200:2001:2001:2001"
        ],
        "CNAME": [
            "test.example.com"
        ],
        "NS": [
            "a.iana-servers.net.",
            "b.iana-servers.net."
        ],
        "domain": "example.com",
        "server": "system"
    }
}
```

## Human Readable Output

>###  Domain DNS Details for example.com
>|domain|server|CNAME|NS|A|AAAA|
>|---|---|---|---|---|---|
>| example.com | system | test.example.com | a.iana-servers.net.,<br/>b.iana-servers.net. | 10.11.12.13 | 2001:2001:200:1:200:2001:2001:2001 |

