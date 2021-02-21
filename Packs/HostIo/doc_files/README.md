This integration is used for Domains enrichment purposes, the data is received from host.io api.
This integration was integrated and tested with version xx of HostIo
## Configure HostIo on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HostIo.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### hostio-domain-search
***
Returns a list of domain associated with a specific field, and the total amount of these domains


#### Base Command

`hostio-domain-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | field name to search a domain according to it. | Required | 
| value | the value of the field. | Required | 
| limit | maximum amount of domains to display, default value is 25. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HostIo.Search.Field | String | The field to look up. | 
| HostIo.Search.Value | String | The value of the given field. | 
| HostIo.Search.Domains | List | some of the domains. | 
| HostIo.Search.Total | Number | The total amount of domins associated with the given field. | 


#### Command Example
``` ```

#### Human Readable Output



### domain
***
Returns Domain information and reputation.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HostIo.Domain.web.rank | Number | a rank that's based on popularity. | 
| HostIo.Domain.web.server | String | name of the server where the domain exist. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | The domain name. | 
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. | 
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. | 
| Domain.Registrant.Name | String | The name of the registrant. | 
| Domain.Registrant.Country | String | The country of the registrant. | 
| Domain.UpdatedDate | Date | The date when the domain was last updated. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.NameServers | String | Name servers of the domain. | 


#### Command Example
``` ```

#### Human Readable Output


