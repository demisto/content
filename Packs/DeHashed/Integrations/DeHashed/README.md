This integration allows you to check if your personal information such as your email, username, or password is being compromised.
This integration was integrated and tested with version xx of DeHashed
## Configure DeHashed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DeHashed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| base_url | Server URL \(e.g. https://example.net\) | True |
| email | Email | True |
| api_key | Api Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dehashed-search
***
search if an information is being compromised.


#### Base Command

`dehashed-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | when choosing "all fields" option, it search the specified given "value", no need to pass "operation" argument as well. | Required | 
| value | searched value | Required | 
| operation | choose a search type that you want to perform | Required | 
| page | A number for result page to get. each page contains up to 5,000 entries. | Optional | 
| results_from | sets a starting point for disply range. Deshased response can have over 5,000 entries. defult value is: 0. | Optional | 
| results_to | sets an end point for disply range. Deshased response can have over 5,000 entries. defult value is: 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeHashed.Search.Id | String | Object's id | 
| DeHashed.Search.Email | String | Object's email | 
| DeHashed.Search.Username | String | Object's username | 
| DeHashed.Search.Password | String | Object's password | 
| DeHashed.Search.HashedPassword | String | Object's hashed password | 
| DeHashed.Search.Name | String | Object's name | 
| DeHashed.Search.Vin | Number | Object's vehicle identification | 
| DeHashed.Search.Address | String | Object's address | 
| DeHashed.Search.IpDddress | Number | Object's ip address | 
| DeHashed.Search.Phone | Number | Object's phone | 
| DeHashed.Search.ObtainedFrom | String | Object's source | 
| Dehashed.LastQuery.ResultsFrom | Number | The "results\_from" value that was passed to the last query. | 
| Dehashed.LastQuery.ResultsTo | Unknown | The "results\_to" value that was passed to the last query. | 
| Dehashed.LastQuery.TotalResults | Number | The total entries that returned from the last query. | 
| Dehashed.LastQuery.DisplayedResults | Number | The number of entries that were displayed in demisto from the last query. | 


#### Command Example
!dehashed-search asset_type=all_fields operation=contains value=or-gal@gmail.com results_to=4 results_from=0
!dehashed-search asset_type=email operation=is value=or-gal@gmail.com page=1
!dehashed-search asset_type=name operation=contains value=gal,gil,test1 results_from=2 results_to=30 page=3
!dehashed-search asset_type=name operation=regex value=joh?n(ath[oa]n)


#### Human Readable Output


