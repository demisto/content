Team Cymru provides various service options dedicated to mapping IP numbers to BGP prefixes and ASNs. Each of the services is based on the same BGP feeds from 50+ BGP peers and is updated at 4-hour intervals.
This integration was integrated and tested with version 1.0 of TeamCymru

## Configure Team Cymru in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Use system proxy settings | False |
| Proxy URL | Supports socks4/socks5/http connect proxies \(e.g., socks5h://host:1080\). | False | 
| Source Reliability | Reliability of the source providing the intelligence data. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Checks the reputation of an IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | An IPv4 address to query, e.g., 1.1.1.1. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address. | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.ASOwner | String | The autonomous system owner of the IP address. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Registrar.Abuse.Network | String | The network of the contact for reporting abuse. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| TeamCymru.IP.Address | String | The IP address. | 
| TeamCymru.IP.ASN | String | The IP ASN. | 
| TeamCymru.IP.ASOwner | String | The IP AS owner. | 
| TeamCymru.IP.Geo.Country | String | The IP country. | 
| TeamCymru.IP.Registrar.Abuse.Network | String | The IP range relevant for abuse inquiries provided for the IP. | 

#### Command example
```!ip ip=1.1.1.1```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Score": 0,
        "Type": "ip",
        "Vendor": "TeamCymru"
    },
    "IP": {
        "ASN": "13335",
        "ASOwner": "CLOUDFLARENET, US",
        "Address": "1.1.1.1",
        "Geo": {
            "Country": "AU"
        },
        "Registrar": {
            "Abuse": {
                "Network": "1.1.1.0/24"
            }
        }
    },
    "TeamCymru": {
        "IP": {
            "ASN": "13335",
            "ASOwner": "CLOUDFLARENET, US",
            "Address": "1.1.1.1",
            "Geo": {
                "Country": "AU"
            },
            "Registrar": {
                "Abuse": {
                    "Network": "1.1.1.0/24"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Team Cymru results for 1.1.1.1
>|IP|ASN|Organization|Country|Range|
>|---|---|---|---|---|
>| 1.1.1.1 | 13335 | CLOUDFLARENET, US | AU | 1.1.1.0/24 |


### cymru-bulk-whois
***
Checks the reputation of a CSV list of IPv4 addresses within a file. 
Note: Results for queries exceeding 10,000 IPs may take more than a minute given a moderately sized Internet link.


#### Base Command

`cymru-bulk-whois`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The file's War Room entry ID. | Required | 
| delimiter | Delimiter by which the content of the file is separated.<br/>Eg:  " , " , " : ", " ; ". Default is ,. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address. | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.ASOwner | String | The autonomous system owner of the IP address. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Registrar.Abuse.Network | String | The network of the contact for reporting abuse. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| TeamCymru.IP.Address | String | The IP address. | 
| TeamCymru.IP.ASN | String | The IP ASN. | 
| TeamCymru.IP.ASOwner | String | The IP AS owner. | 
| TeamCymru.IP.Geo.Country | String | The IP country. | 
| TeamCymru.IP.Registrar.Abuse.Network | String | The IP range relevant for abuse inquiries provided for the IP. | 

#### Command example
```!cymru-bulk-whois entry_id=${File.EntryID}```


## Troubleshooting
- In case of a problem with the proxy configuration, validate that the given proxy is working with the Whois content pack. 