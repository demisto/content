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
| DomainDNSDetails | The returned details | Unknown |


## Script Example
```!GetDomainDNSDetails domain=paloaltonetworks.com```

## Context Example
```json
{
    "DomainDNSDetails": {
        "A": [
            "34.107.151.202"
        ],
        "NS": [
            "ns5.dnsmadeeasy.com.",
            "ns6.dnsmadeeasy.com.",
            "ns7.dnsmadeeasy.com.",
            "ns1.p23.dynect.net.",
            "ns2.p23.dynect.net.",
            "ns3.p23.dynect.net.",
            "ns4.p23.dynect.net."
        ],
        "domain": "paloaltonetworks.com",
        "server": "system"
    }
}
```

## Human Readable Output

>###  Domain DNS Details for paloaltonetworks.com
>|domain|server|CNAME|NS|A|AAAA|
>|---|---|---|---|---|---|
>| paloaltonetworks.com | system |  | ns5.dnsmadeeasy.com.,<br/>ns6.dnsmadeeasy.com.,<br/>ns7.dnsmadeeasy.com.,<br/>ns1.p23.dynect.net.,<br/>ns2.p23.dynect.net.,<br/>ns3.p23.dynect.net.,<br/>ns4.p23.dynect.net. | 34.107.151.202 |  |

