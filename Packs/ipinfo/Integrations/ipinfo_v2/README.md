Use the IPinfo.io API to get data about an IP address.

## Differences from IPinfo (v1)

- The `ip-field` command has been removed on v2: all outputs are available by running `ip`.
- IPinfo v2 Allows setting source reliability.
- IPinfo v2 Enriches data with IP-hostname relationships.

## Configure IPinfo v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Token | The API key to use for the connection. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Base URL |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Check IP reputation (when information is available, returns a JSON with details). Uses all configured Threat Intelligence feeds.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to query, e.g., 1.1.1.1. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPinfo.IP.Address | String | The IP address. | 
| IPinfo.IP.Hostname | String | The IP hostname. | 
| IPinfo.IP.ASN | String | The IP ASN. | 
| IPinfo.IP.ASOwner | String | The IP AS owner. | 
| IPinfo.IP.Organization.Name | String | The IP organization name \(Only available in some IPinfo.io plans\). | 
| IPinfo.IP.Organization.Type | String | The IP organization type \(Only available in some IPinfo.io plans\). | 
| IPinfo.IP.Geo.Location | String | The IP geographic location \(coordinates as lat:lon\). | 
| IPinfo.IP.Geo.Country | String | The IP country. | 
| IPinfo.IP.Geo.Description | String | The IP location as &lt;City, Region, Postal Code, Country&gt;. | 
| IPinfo.IP.Registrar.Abuse.Address | String | The physical address registered for receiving abuse reports for the IP. \(Only available in some IPinfo.io plans\). | 
| IPinfo.IP.Registrar.Abuse.Country | String | The country where abuse reports are received for the IP. \(Only available in some IPinfo.io plans\). | 
| IPinfo.IP.Registrar.Abuse.Email | String | The email address for abuse reports provided by the IP. \(Only available in some IPinfo.io plans\). | 
| IPinfo.IP.Registrar.Abuse.Name | String | The name of the abuse report handler received for the IP. \(Only available in some IPinfo.io plans\). | 
| IPinfo.IP.Registrar.Abuse.Network | String | The IP range relevant for abuse inquiries provided for the IP. \(Only available in some IPinfo.io plans\). | 
| IP.Address | String | The IP address. | 
| IP.Hostname | String | The IP hostname. | 
| IP.ASN | String | The IP ASN. | 
| IP.Tags | String | Tags related the IP use \(hosting, proxy, tor, vpn\). | 
| IP.FeedRelatedIndicators.value | String | Names of indicators associated with the IP. | 
| IP.FeedRelatedIndicators.type | String | Types of indicators associated with the IP. | 
| IP.Relationships.EntityA | string | The source of the relationship. | 
| IP.Relationships.EntityB | string | The destination of the relationship. | 
| IP.Relationships.Relationship | string | The name of the relationship. | 
| IP.Relationships.EntityAType | string | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. | 
| IP.Geo.Location | String | The IP geographic location \(coordinates as lat:lon\) | 
| IP.Geo.Country | String | The IP country. | 
| IP.Geo.Description | String | The IP location as &lt;City, Region, Postal Code, Country&gt;. | 
| IP.Organization.Name | String | The organization of the IP. | 
| IP.Organization.Type | String | The organization type of the IP. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | How reliable the score is \(for example, "C - fairly reliable"\). | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 

#### Command example
```!ip ip=1.1.1.1```
#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.1.1.1",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "ip",
        "Vendor": "ipinfo_v2"
    },
    "IP": {
        "ASN": "AS13335",
        "Address": "1.1.1.1",
        "FeedRelatedIndicators": [
            {
                "description": "Hostname",
                "type": "URL",
                "value": "one.one.one.one"
            },
            {
                "description": "AS domain",
                "type": "Domain",
                "value": "cloudflare.com"
            },
            {
                "description": "Company domain",
                "type": "Domain",
                "value": "cloudflare.com"
            }
        ],
        "Geo": {
            "Country": "US",
            "Description": "Los Angeles, California, 90076, US",
            "Location": "34.0522:-118.2437"
        },
        "Hostname": "one.one.one.one",
        "Organization": {
            "Name": "APNIC and Cloudflare DNS Resolver project",
            "Type": "hosting"
        },
        "Relationships": [
            {
                "EntityA": "1.1.1.1",
                "EntityAType": "IP",
                "EntityB": "one.one.one.one",
                "EntityBType": "Domain",
                "Relationship": "resolves-to"
            }
        ],
        "Tags": "hosting"
    },
    "IPinfo": {
        "IP": {
            "ASN": "AS13335",
            "ASOwner": "Cloudflare, Inc.",
            "Address": "1.1.1.1",
            "Geo": {
                "Country": "US",
                "Description": "Los Angeles, California, 90076, US",
                "Location": "34.0522,-118.2437"
            },
            "Hostname": "one.one.one.one",
            "Organization": {
                "Name": "APNIC and Cloudflare DNS Resolver project",
                "Type": "hosting"
            },
            "Registrar": {
                "Abuse": {
                    "Address": "PO Box 3646, South Brisbane, QLD 4101, Australia",
                    "Country": "AU",
                    "Email": "test",
                    "Name": "APNIC RESEARCH",
                    "Network": "1.1.1.0/24",
                    "Phone": "+61-7-3858-3188"
                }
            },
            "Tags": [
                "hosting"
            ]
        }
    }
}
```

#### Human Readable Output

### IPinfo results for 1.1.1.1

|anycast|city|country|hostname|ip|loc|org|postal|readme|region|timezone|
|---|---|---|---|---|---|---|---|---|---|---|
| true | Miami | US | one.one.one.one | 1.1.1.1 | 25.7867,-80.1800 | AS13335 Cloudflare, Inc. | 33132 | https