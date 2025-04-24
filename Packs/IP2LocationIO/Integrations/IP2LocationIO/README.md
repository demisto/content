IP2Location.io integration to query IP geolocation data.
## Configure IP2LocationIO in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| IP2Location.io API |  | True |
| API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ip

***
Return IP information and reputation

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP2LocationIO.IP.asn | String | The autonomous system name for the IP address. | 
| IP2LocationIO.IP.asn_description | String | The ASN description. | 
| IP2LocationIO.IP.ip | String | The actual IP address. | 
| IP2LocationIO.IP.query | String | IP address that was queried. | 
| IP2LocationIO.IP.raw | Unknown | Additional raw data for the IP address. | 
| IP.Address | String | IP address. | 
| IP.ASN | String | The autonomous system name for the IP address. | 
| IP.Relationships.EntityA | string | The source of the relationship. | 
| IP.Relationships.EntityB | string | The destination of the relationship. | 
| IP.Relationships.Relationship | string | The name of the relationship. | 
| IP.Relationships.EntityAType | string | The type of the source of the relationship. | 
| IP.Relationships.EntityBType | string | The type of the destination of the relationship. | 