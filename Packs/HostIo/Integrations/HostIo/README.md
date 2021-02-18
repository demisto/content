This is the HostIo integration for getting detailed information 
about domains, for example: what IP address are they hosted on
and description about these domains 


## Configure HostIo on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HostIo
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| token | API Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### domain
***
Returns Domain information and reputation.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Optional | 

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
| Domain.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| Domain.NameServers | String | Name servers of the domain. | 
| Domain.WHOIS.NameServers | String | A CSV string of name servers, for example 'ns1.bla.com, ns2.bla.com'. | 
| Domain.WHOIS.CreationDate | Date | The creation date of the domain. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| Domain.WHOIS.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 \(i.e. '2020\-04\-30T10:35:00.000Z'\). | 
| Domain.WHOIS.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.WHOIS.Registrar.Name | String | The name of the registrar, for example 'GoDaddy' |


#### Command Example
```!domain domain="google.com"```

### context Example
```
{
    "domain": "google.com",
    "web": {
        "domain": "google.com",
        "rank": 1,
        "url": "https://www.google.com/?gws_rd=ssl",
        "ip": "172.217.14.196",
        "date": "2021-01-26T01:33:56.129Z",
        "length": 192888,
        "server": "gws",
        "encoding": "utf8",
        "title": "Google",
        "description": "Search the world's information, including webpages, images, videos and more. Google has many special features to help you find exactly what you're looking for.",
        "email": "robert@broofa.com",
        "links": [
            "about.google"
        ]
    },
    "dns": {
        "domain": "google.com",
        "a": [
            "172.217.14.238"
        ],
        "aaaa": [
            "2607:f8b0:400a:803::200e"
        ],
        "mx": [
            "10 aspmx.l.google.com.",
            "20 alt1.aspmx.l.google.com.",
            "30 alt2.aspmx.l.google.com.",
            "40 alt3.aspmx.l.google.com.",
            "50 alt4.aspmx.l.google.com."
        ],
        "ns": [
            "ns1.google.com.",
            "ns2.google.com.",
            "ns3.google.com.",
            "ns4.google.com."
        ]
    },
    "ipinfo": {
        "172.217.14.196": {
            "city": "Seattle",
            "region": "Washington",
            "country": "US",
            "loc": "47.6062,-122.3321",
            "postal": "98111",
            "timezone": "America/Los_Angeles",
            "asn": {
                "asn": "AS15169",
                "name": "Google LLC",
                "domain": "google.com",
                "route": "172.217.14.0/24",
                "type": "business"
            }
        },
        "172.217.14.238": {
            "city": "Seattle",
            "region": "Washington",
            "country": "US",
            "loc": "47.6062,-122.3321",
            "postal": "98111",
            "timezone": "America/Los_Angeles",
            "asn": {
                "asn": "AS15169",
                "name": "Google LLC",
                "domain": "google.com",
                "route": "172.217.14.0/24",
                "type": "business"
            }
        },
        "2607:f8b0:400a:803::200e": {
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "postal": "94043",
            "timezone": "America/Los_Angeles",
            "asn": {
                "asn": "AS15169",
                "name": "Google LLC",
                "domain": "google.com",
                "route": "2607:f8b0:400a::/48",
                "type": "business"
            }
        }
    },
    "related": {
        "ip": [
            {
                "value": "172.217.14.196",
                "count": 123993
            },
            {
                "value": "172.217.14.238",
                "count": 94689
            },
            {
                "value": "2607:f8b0:400a:803::200e",
                "count": 585
            }
        ],
        "asn": [
            {
                "value": "AS15169",
                "count": 51782915
            }
        ],
        "ns": [
            {
                "value": "google.com",
                "count": 141664
            }
        ],
        "mx": [
            {
                "value": "google.com",
                "count": 13815108
            }
        ],
        "email": [
            {
                "value": "robert@broofa.com",
                "count": 1483
            }
        ],
        "backlinks": [
            {
                "value": "google.com",
                "count": 8638260
            }
        ],
        "redirects": [
            {
                "value": "google.com",
                "count": 943992
            }
        ]
    }
}
```

### hostio-domain-search
***
get a list of domains that are associated with a specific field


#### Base Command

`hostio-domain-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | the field to look up | Required | 
| value | the provided value to the given field | Required | 
| limit | maximum amount of domain to display | Not Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Field| String | the field to look up | 
| value | String | the provided value to the given field | 
| Domain | List | list of a number of domains associated with field | 
| total | Number | the total amount of domains associated with field | 

#### Command Example
```!hostio-domain-search field="twitter" value="elonmusk" limit=5```
### context Example
```
{
    "twitter": "elonmusk",
    "total": 283,
    "domains": [
        "dogeclicks.com",
        "teslaupdates.co",
        "smart-rus.com",
        "akhil.ai",
        "adoystore.com"
    ]
}
```

