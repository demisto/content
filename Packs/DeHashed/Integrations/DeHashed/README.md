This integration allows you to check if your personal information such as your email, username, or password is being compromised.
This integration was integrated and tested with version xx of DeHashed
## Configure DeHashed on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DeHashed.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### dehashed-search
***
Performs a search to check if information is compromised.


#### Base Command

`dehashed-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | If you select the "all fields" option, the search is performed on all fields with the specified value entered in the "value" argument, and you don't have to pass the "operation" argument. | Required | 
| value | The searched value. | Required | 
| operation | Search operator. Can be "is", "contains", or "regex". | Required | 
| page | The number of page to return. Each page contains a maximum of 5,000 results. entries. | Optional | 
| results_from | Starting result number to display. Default is 0. Dehashed response can include more than 5,000 results. | Optional | 
| results_to | Ending result number to display. Default is 100. Dehashed response can include more than 5,000 results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeHashed.Search.Id | String | ID of the object. | 
| DeHashed.Search.Email | String | Email address of the object. | 
| DeHashed.Search.Username | String | Username of the object. | 
| DeHashed.Search.Password | String | Password of the object. | 
| DeHashed.Search.HashedPassword | String | Hashed password of the object. | 
| DeHashed.Search.Name | String | Name of the object. | 
| DeHashed.Search.Vin | Number | Vehicle identification of the object. | 
| DeHashed.Search.Address | String | Address of the object. | 
| DeHashed.Search.IpDddress | Number | IP address of the object. | 
| DeHashed.Search.Phone | Number | Phone number of the object. | 
| DeHashed.Search.ObtainedFrom | String | Source of the object. | 
| Dehashed.LastQuery.ResultsFrom | Number | The value of the "results\_from" argument that was passed in the last query. | 
| Dehashed.LastQuery.ResultsTo | Unknown | The value of the "results\_to" argument that was passed in the last query. | 
| Dehashed.LastQuery.TotalResults | Number | The total number of entries returned from the last query. | 
| Dehashed.LastQuery.DisplayedResults | Number | The number of entries that were displayed in Cortex XSOAR from the last query. | 


#### Command Example
!dehashed-search asset_type=all_fields operation=contains value=or-gal@gmail.com results_to=4 results_from=0
!dehashed-search asset_type=email operation=is value=or-gal@gmail.com page=1
!dehashed-search asset_type=name operation=contains value=gal,gil,test1 results_from=2 results_to=30 page=3
!dehashed-search asset_type=name operation=regex value=joh?n(ath[oa]n)


#### Human Readable Output


