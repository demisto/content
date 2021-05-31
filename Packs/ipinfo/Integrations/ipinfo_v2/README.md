Use the IPinfo.io API to get data about an IP address. 

## Configure ipinfo_v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ipinfo_v2.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Description** | **Required** |
       | --- | --- | --- |
   | API Token | The API Key to use for connection | True |
   | Source Reliability | Reliability of the source providing the intelligence data. | True |
   | Base URL |  | True |
   | Trust any certificate (not secure) |  | False |
   | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Check IP reputation (when information is available, returns a JSON with details).  Uses all configured Threat Intelligence feeds


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to query (e.g. 1.1.1.1) | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPinfo.IP.Address | String | The IP address | 
| IPinfo.IP.Hostname | String | The IP Hostname | 
| IPinfo.IP.ASN | String | The IP ASN | 
| IPinfo.IP.ASOwner | String | The IP AS Owner | 
| IPinfo.IP.Organization.Name | String | The IP organization name \(Only available in some IPinfo.io plans\) | 
| IPinfo.IP.Organization.Type | String | The IP organization type \(Only available in some IPinfo.io plans\) | 
| IPinfo.IP.Geo.Location | String | The IP geographic location \(coordinates as lat:lon\) | 
| IPinfo.IP.Geo.Country | String | The IP Country | 
| IPinfo.IP.Geo.Description | String | The IP location as &lt;City, Region, Postal Code, Country&gt; | 
| IPinfo.IP.Registrar.Abuse.Address | String | The physical address registered for receiving abuse reports for the IP. \(Only available in some IPinfo.io plans\) | 
| IPinfo.IP.Registrar.Abuse.Country | String | The country where abuse reports are received for the IP. \(Only available in some IPinfo.io plans\) | 
| IPinfo.IP.Registrar.Abuse.Email | String | The email address for abuse reports provided by the IP. \(Only available in some IPinfo.io plans\) | 
| IPinfo.IP.Registrar.Abuse.Name | String | The name of the abuse report handler received for the IP. \(Only available in some IPinfo.io plans\) | 
| IPinfo.IP.Registrar.Abuse.Network | String | The IP range relevant for abuse inquries provided for the IP \(Only available in some IPinfo.io plans\) | 
| IP.Address | String | The IP address | 
| IP.Hostname | String | The IP Hostname | 
| IP.ASN | String | The IP ASN | 
| IP.Tags | String | Tags related the IP use \(hosting, proxy, tor, vpn\) | 
| IP.FeedRelatedIndicators.value | String | Names of indicators associated with the IP | 
| IP.FeedRelatedIndicators.type | String | Types of indicators associated with the IP | 
| IP.Relationships.EntityA | String | The source of the relationship. | 
| IP.Relationships.EntityB | String | The destination of the relationship. | 
| IP.Relationships.Relationship | String | The name of the relationship. | 
| IP.Relationships.EntityAType | String | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | String | The type of the destination of the relationship. | 
| IP.Relationships.Relationship | String | The name of the relationship. | 
| IP.Geo.Location | String | The IP geographic location \(coordinates as lat:lon\) | 
| IP.Geo.Country | String | The IP Country | 
| IP.Geo.Description | String | The IP location as &lt;City, Region, Postal Code, Country&gt; | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | How reliable the score is \(for example, "C - fairly reliable"\) | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 


#### Command Example
```!ip ip=1.1.1.1```

#### Context Example
```json
{
    "DBotScore": [
        {
            "Indicator": "1.1.1.1",
            "Reliability": "C - Fairly reliable",
            "Score": 0,
            "Type": "ip",
            "Vendor": "IPinfo_v2"
        }
    ],
    "IP": {
        "ASN": 13335,
        "Address": "1.1.1.1",
        "FeedRelatedIndicators": [
            {
                "description": "Hostname",
                "type": "URL",
                "value": "one.one.one.one"
            }
        ],
        "Geo": {
            "Country": "AU"
        },
        "Hostname": "one.one.one.one",
        "Relationships": [
            {
                "EntityA": "1.1.1.1",
                "EntityAType": "IP",
                "EntityB": "one.one.one.one",
                "EntityBType": "Domain",
                "Relationship": "resolves-to"
            }
        ],
    },
    "IPinfo": {
        "IP": {
            "ASN": "AS13335",
            "ASOwner": "Cloudflare, Inc.",
            "Address": "1.1.1.1",
            "Geo": {
                "Country": "US",
                "Description": "Miami, Florida, 33132, US",
                "Location": "25.7867,-80.1800"
            },
            "Hostname": "one.one.one.one",
            "Organization": null,
            "Registrar": null,
            "Tags": []
        }
    }
}
```

#### Human Readable Output

### IPinfo results for 1.1.1.1

|anycast|city|country|hostname|ip|loc|org|postal|readme|region|timezone|
|---|---|---|---|---|---|---|---|---|---|---|
| true | Miami | US | one.one.one.one | 1.1.1.1 | 25.7867,-80.1800 | AS13335 Cloudflare, Inc. | 33132 | https
