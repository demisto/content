Use the ipinfo.io API to get data about an IP address
## Configure ipinfo on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ipinfo.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| proxy | Use system proxy settings | False |
| token | API Token \(optional\) | False |
| insecure | Trust any certificate \(not secure\) | False |
| use_https | Use HTTPS connections | False |

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
| ip | IP address to query. E.g. !ip 1.1.1.1 | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address | 
| IP.Hostname | String | The IP hostname | 
| IP.ASN | String | The IP ASN | 
| IP.Geo.Location | String | The IP geographic location in coordinates | 
| IP.Geo.Country | String | The IP country | 
| IP.Geo.Description | String | The IP location as \<City, Region, Postal Code, Country\> | 
| IP.ASOwner | string | The IP AS owner |
| IP.FeedRelatedIndicators.value | string | Indicators that are associated with the IP |
| IP.FeedRelatedIndicators.type | string | The type of the indicators that are associated with the IP |
| IP.Tags | string | Tags that are associated with the IP |
| IP.Registrar.Abuse.Address | string | The IP registrar abuse address |
| IP.Registrar.Abuse.Country | string | The IP registrar abuse country |
| IP.Registrar.Abuse.Name | string | The IP registrar abuse name |
| IP.Registrar.Abuse.Network | string | The IP registrar abuse network |
| IP.Registrar.Abuse.Phone | string | The IP registrar abuse phone |
| IP.Registrar.Abuse.Email | string | The IP registrar abuse email |
| IP.Organization.Name | string | The IP organization name |
| IP.Organization.Type | string | The IP organization type |
| DBotScore.Indicator | string | The indicator that was tested. |
| DBotScore.Type | string | The indicator type. |
| DBotScore.Vendor | string | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

#### Command Example
``` !ip ip=1.1.1.1 ```

#### Human Readable Output

| Key | Value | 
| --- | --- |
| city | Miami | 
| country | US | 
| hostname | one.one.one.one | 
| ip | 1.1.1.1 | 
| loc | 25.7867,-80.1800 | 
| org | AS13335 Cloudflare, Inc. | 
| postal | 33132 | 
| readme | https://ipinfo.io/missingauth | 
| region | Florida | 
| timezone | America/New_York | 


### ipinfo_field
***
Retrieve value for a specific field from the IP address information


#### Base Command

`ipinfo_field`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to query. E.g. !ip 1.1.1.1 | Required | 
| field | Name of the field to retrieve. Can be org, city, geo, etc. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !ipinfo_field ip=1.1.1.1 field=city ```

#### Human Readable Output
Miami

