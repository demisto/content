Use the HostIo integration to enrich Domains using the Host.io API.
This integration was integrated and tested with version 1.0.0 of HostIo
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
Returns a list of domains associated with a specific field, and the total amount of these domains


#### Base Command

`hostio-domain-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field | Field name to search a Domain according to it. Possible values are: ip, ns, mx, asn, backlinks, redirects, adsense, facebook, twitter, instagram, gtm, googleanalytics, email. | Required | 
| value | The value of the given field. | Required | 
| limit | The maximum number of domains to display, must be one of 0, 1, 5, 10, 25, 100, 250, or 1000, The default value is 25. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HostIo.Search.Field | String | The field to look up. | 
| HostIo.Search.Value | String | The value of the given field. | 
| HostIo.Search.Domains | Unknown | List of Domains associated with the given field. | 
| HostIo.Search.Total | Number | The total amount of domains associated with the given field. | 


#### Command Example
``` ```

#### Human Readable Output



### domain
***
Returns Domain information.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HostIo.Domain.web.rank | Number | A rank that's based on popularity. | 
| HostIo.Domain.web.server | String | Name of the server where the domain exist. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | String | The Domain name. | 
| Domain.Registrant.Name | String | The name of the Registrant. | 
| Domain.Registrant.Country | String | The country of the Registrant. | 
| Domain.UpdatedDate | Date | The date when the Domain was last updated. Format is ISO8601 \(i.e. '2020-04-30T10:35:00.000Z'\). | 
| Domain.NameServers | String | Name of the server where the domain exist. | 


#### Command Example
``` ```

#### Human Readable Output


