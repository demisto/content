Enrich indicators using the Spur Context API.
This integration was integrated and tested with version 2 of SpurContextAPI.

## Configure SpurContextAPI in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://api.spur.us/) |  | False |
| API Token |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### spur-context-api-enrich

***
Enrich indicators using the Spur Context API.

#### Base Command

`spur-context-api-enrich`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to enrich. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SpurContextAPI.Context.ip | string | IP that was enriched | 
| SpurContextAPI.Context.as | object | Autonomous System details for an IP Address. | 
| SpurContextAPI.Context.organization | string | The organization using this IP address. | 
| SpurContextAPI.Context.infrastructure | string | The primary infrastructure type that this IP address supports. Common tags are MOBILE and DATACENTER. | 
| SpurContextAPI.Context.location | object | Data-center or IP Hosting location based on MaxMind GeoLite. | 
| SpurContextAPI.Context.services | array | The different types of proxy or VPN services that are running on this IP address | 
| SpurContextAPI.Context.tunnels | array | Different VPN or proxy tunnels that are currently in-use on this IP address | 
| SpurContextAPI.Context.risks | array | Risks that we have determined based on our collection of data. | 
| SpurContextAPI.Context.client_concentration | object | The strongest location concentration for clients using this IP address. | 
| SpurContextAPI.Context.client_countries | number | The number of countries that we have observed clients located in for this IP address | 
| SpurContextAPI.Context.client_spread | number | The total geographic area in kilometers where we have observed users | 
| SpurContextAPI.Context.client_proxies | array | The different types of callback proxies we have observed on clients using this IP address. | 
| SpurContextAPI.Context.client_count | number | The average number of clients we observe on this IP address. | 
| SpurContextAPI.Context.client_behaviors | array | An array of behavior tags for an IP Address. | 
| SpurContextAPI.Context.client_types | array | The different type of client devices that we have observed on this IP address. | 
### ip

***
IP reputation command using the Spur Context API.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to enrich. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Score | string | The actual score. | 
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | string | IP address. | 
| IP.ASN | string | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.ASOwner | String | The autonomous system owner of the IP. | 
| IP.ClientTypes | array | The organization name. | 
| IP.Geo.Country | string | The country in which the IP address is located. | 
| IP.Organization.Name | string | The organization name. | 
| IP.Risks | array | Risks that we have determined based on our collection of data. | 
| IP.Tunnels | array | The different types of proxy or VPN services that are running on this IP address. | 
| SpurContextAPI.Context.ip | string | IP that was enriched. | 
| SpurContextAPI.Context.as | object | Autonomous System details for an IP Address. | 
| SpurContextAPI.Context.organization | string | The organization using this IP address. | 
| SpurContextAPI.Context.infrastructure | string | The primary infracstructure type that this IP address supports. Common tags are MOBILE and DATACENTER. | 
| SpurContextAPI.Context.location | object | Data-center or IP Hosting location based on MaxMind GeoLite. | 
| SpurContextAPI.Context.services | array | The different types of proxy or VPN services that are running on this IP address. | 
| SpurContextAPI.Context.tunnels | array | Different VPN or proxy tunnels that are currently in-use on this IP address. | 
| SpurContextAPI.Context.risks | array | Risks that we have determined based on our collection of data. | 
| SpurContextAPI.Context.client_concentration | object | The strongest location concentration for clients using this IP address. | 
| SpurContextAPI.Context.client_countries | number | The number of countries that we have observed clients located in for this IP address. | 
| SpurContextAPI.Context.client_spread | number | The total geographic area in kilometers where we have observed users. | 
| SpurContextAPI.Context.client_proxies | array | The different types of callback proxies we have observed on clients using this IP address. | 
| SpurContextAPI.Context.client_count | number | The average number of clients we observe on this IP address. | 
| SpurContextAPI.Context.client_behaviors | array | An array of behavior tags for an IP Address. | 
| SpurContextAPI.Context.client_types | array | The different type of client devices that we have observed on this IP address. | 

