Query dns names over https from Cloudflare or Google.

## Configure DNSOverHttps in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| DNS over HTTPS resolver | Select Cloudflare or Google DNS over HTTPS server to use | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### doh-resolve
***
Resolve a name to IP over HTTPS


#### Base Command

`doh-resolve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | domain you want to resolve to IP. | Required | 
| type | Type of DNS records you want to get. Possible values are: A, AAAA, TXT, MX, DNSKEY, NS. Default is A. | Optional | 
| only_answers | If you only want to return the answers. Possible values are: True, False. Default is True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DNSOverHTTPS.Results | List | DNS query results | 


#### Command Example
```!doh-resolve domain=domain.com```

#### Context Example
```json
{
    "DNSOverHTTPS": {
        "Results": [
            {
                "TTL": 3600,
                "data": "domain.com.edgekey.net.",
                "name": "www.domain.com",
                "type": 5
            },
            {
                "TTL": 21600,
                "data": "e3130.dscg.net.",
                "name": "domain.com.edgekey.net",
                "type": 5
            },
            {
                "TTL": 20,
                "data": "111.11.11.111",
                "name": "e3130.dscg.net",
                "type": 1
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|TTL|data|name|type|
>|---|---|---|---|
>| 3600 | domain.com.edgekey.net. | www.domain.com | 5 |
>| 21600 | e3130.dscg.net. | domain.com.edgekey.net | 5 |
>| 20 | 111.11.11.111 | e3130.dscg.net | 1 |