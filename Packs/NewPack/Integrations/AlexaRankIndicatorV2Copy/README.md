Alexa provides website ranking information that can be useful when determining if a domain has a strong web presence.
This integration was integrated and tested with version xx of Alexa Rank Indicator v2_copy

## Configure Alexa Rank Indicator v2_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Alexa Rank Indicator v2_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base API URL |  | True |
    | API Key |  | True |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Rank Threshold For Suspicious Domain | If the domain's Alexa rank is over this threshold, the domain is marked as suspicious. If the rank is between the threshold for suspicious domains and top domains, the domain is marked as unknown. | False |
    | Rank Threshold For Top Domains | If the domain's Alexa rank is under this threshold, the domain is considered trusted and marked as good. If the rank is between the threshold for suspicious domains and top domains, the domain is marked as unknown. | True |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### domain
***
Provides an Alexa ranking of the domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain(s) to search. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain being checked. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| Alexa.Domain.Indicator | String | The domain being checked. | 
| Alexa.Domain.Name | String | The domain being checked. | 
| Alexa.Domain.Rank | String | Alexa rank as determined by Amazon. | 


#### Command Example
``` ```

#### Human Readable Output


