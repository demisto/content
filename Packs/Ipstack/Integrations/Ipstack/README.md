One of the leading IP to geolocation 
APIs and global IP database services.

## Configure ipstack in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Queries an IP address in ipstack.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to query. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | string | IP address. | 
| IP.Geo.Location | string | Latitude and longitude of the IP address. | 
| IP.Geo.Country | string | Country of origin of the IP address. | 
| Ipstack.IP.address | string | IP address. | 
| Ipstack.IP.type | string | IP type \(ipv4 or ipv6\). | 
| Ipstack.IP.continent_name | string | Continent of the IP address. | 
| Ipstack.IP.latitude | string | Latitude of the IP address. | 
| Ipstack.IP.longitude | string | Longitude of the IP address. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | How reliable the score is \(for example, "C - fairly reliable"\). | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 