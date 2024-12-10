Use the JsonWhoIs integration to  enrich domain indicators.


## Configure JsonWhoIs in Cortex


| **Parameter** | **Description** | **Example** |
| ---------             | -----------           | -------            |
| Name | A meaningful name for the integration instance. | JsonWhoIs_instance_1 |
| API Token  |  Your [JsonWhoIs API token](https://jsonwhois.com/) |  N/A  |
| System proxy | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration.     | https:/<span></span>/proxyserver.com |
| Trust any certificate (not secure) | When selected, certificates are not checked. | N/A |
| Do Not Use by Default  | If checked the commands will not be used by default (this is influenced if two command are the same). | N/A  |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get enriched data

Returns enriched data for Domains, URLs, and IP addresses.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


##### Base Command

`whois`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The URL, IP address, or domain to enrich. | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.WHOIS.DomainStatus | Boolean | Whether the domain is registered. |
| Domain.WHOIS.NameServers | String | The name servers. |
| Domain.WHOIS.CreationDate | Date | The creation date. |
| Domain.WHOIS.UpdatedDate | Date | The updated date. |
| Domain.WHOIS.ExpirationDate | Date | The expiration date. |
| Domain.WHOIS.Registrant.Name | String | The registrant name. |
| Domain.WHOIS.Registrant.Email | String | The registrant email. |
| Domain.WHOIS.Registrant.Phone | String | The registrant phone. |
| Domain.WHOIS.Registrar.Name | String | The registrar name. |
| Domain.WHOIS.Registrar.Url | String | The registrar email. |
| Domain.WHOIS.Registrar.Organization | String | The registrar organization name. |
| Domain.WHOIS.Registrar.Id | Number | The registrar ID. |
| Domain.WHOIS.Admin.Name | String | The Admin name. |
| Domain.WHOIS.Admin.Email | String | The Admin email. |
| Domain.WHOIS.Admin.Phone | String | The Admin phone. |

##### Command Example
```
!whois query=demisto.com
```

##### Context Example
```
{
    "Domain": {
        "WHOIS": {
            "Admin": [
                {
                    "Email": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com",
                    "Name": "WhoisGuard Protected",
                    "Phone": "+507.8365503"
                }
            ],
            "CreationDate": "2015-01-16T21:36:27.000Z",
            "DomainStatus": "registered",
            "ExpirationDate": "2026-01-16T21:36:27.000Z",
            "NameServers": [
                {
                    "Name": "pns31.cloudns.net"
                },
                {
                    "Name": "pns32.cloudns.net"
                },
                {
                    "Name": "pns33.cloudns.net"
                },
                {
                    "Name": "pns34.cloudns.net"
                }
            ],
            "Registrant": [
                {
                    "Email": "5be9245893ff486d98c3640879bb2657.protect@whoisguard.com",
                    "Name": "WhoisGuard Protected",
                    "Phone": "+507.8365503"
                }
            ],
            "Registrar": {
                "Id": "1068",
                "Name": "NameCheap, Inc.",
                "Url": "http://www.namecheap.com"
            },
            "UpdatedDate": "2019-05-14T16:14:12.000Z"
        }
    }
}
```

##### Human Readable Output

##### Admin account

| **Email** | **Name** | **Phone** |
| --- | --- | --- |
| 5be9245893ff486d98c3640879bb2657.protect<span></span>@whoisguard.com | WhoisGuard Protected | +507.8365503 |

##### Name servers

| **Name** |
| --- |
| pns31.cloudns<span></span>.net |
| pns32.cloudns<span></span>.net |
| pns33.cloudns<span></span>.net |
| pns34.cloudns<span></span>.net |

##### Registrant

| **Email** | **Name** | **Phone** |
| --- | --- | --- |
| 5be9245893ff486d98c3640879bb2657.protect<span></span>@whoisguard.com | WhoisGuard Protected | +507.8365503 |

##### Registrar

| **Id** | **Name** | **Url** |
| --- | --- | --- |
| 1068 | NameCheap, Inc. | http:/<span></span>/www<span></span>.namecheap<span></span>.com |

##### Others

| **CreationDate** | **DomainStatus** | **ExpirationDate** | **UpdatedDate** |
| --- | --- | --- | --- |
| 2015-01-16T21:36:27.000Z | registered | 2026-01-16T21:36:27.000Z | 2019-05-14T16:14:12.000Z |

## Troubleshooting

The JsonWhoIs API is not stable. We recommend attempting a query three times before considering the query to fail.