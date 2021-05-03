Use the IPinfo.io API to get data about an IP address. 

## Configure ipinfo_v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ipinfo_v2.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Description** | **Required** |
       | --- | --- | --- |
   | API Token | The API Key to use for connection | True |
   | Source Reliability | Reliability of the source providing the intelligence data. | True |
   | Base URL |  | False |
   | Trust any certificate (not secure) |  | False |
   | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Check IP reputation (when information is available, returns a JSON with details). Uses all configured Threat
Intelligence feeds

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to query. E.g. !ip 1.1.1.1. | Required | 

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
| IP.ASOwner | String | The IP AS Owner | 
| IP.Tags | String | Tags related the IP use \(hosting, proxy, tor, vpn\) | 
| IP.FeedRelatedIndicators.value | String | Names of indicators associated with the IP | 
| IP.FeedRelatedIndicators.type | String | Types of indicators associated with the IP | 
| IP.Geo.Location | String | The IP geographic location \(coordinates as lat:lon\) | 
| IP.Geo.Country | String | The IP Country | 
| IP.Geo.Description | String | The IP location as &lt;City, Region, Postal Code, Country&gt; | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | How reliable the score is \(for example, _"C - fairly reliable_"\) | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 

#### Command Example

```!ip ip=1.1.1.1```

#### Human Readable Output


