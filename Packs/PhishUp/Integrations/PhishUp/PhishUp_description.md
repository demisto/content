 ## PhishUp Real Time Cyber Threat Analytics

If you don't have PhishUp Account or you have any questions about PhishUp please contact with us. 
Also you can visit and test [PhishUp Web Demo](https://www.phishup.co/homepage).

concat details: [info@diatics.com](info@phishup.co)


------
## Configure PhishUp on Cortex XSOAR

1. PhishUp Integration Requirements.

    | **Parameter** | **Required** |
    | --- | --- |
    | Username | True |
    | Password | True |
    | PhishUp API URL | True |
    | PhishUp Action | True |

2. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### phishup-check-urls
***
Get URLs reputation


#### Base Command

`phishup-check-urls`
#### Input

| **Argument Name** | **Description** | **Required** | **Usage** |
| --- | --- | --- | --- |
| Urls | List of URLs for asking to PhishUp Bulk API. | Required | 1- Comma delimitered text like "example.net, example.com" 2- Single url "example.net" 3- List of URLs like "['exapmle.net', 'exapmle.com']" (a list with 2 string elements) 


#### Context Output

| **Path** | **Type** | **Description** | **Results** |
| --- | --- | --- | --- |
| PhishUp.Result | String | Single PhishUp Response for All URLs | Phish, Clean, Error


PhishUp.Result gives only one response for bulk list. If you want all reponses from PhishUp you need to process raw response (Json Response).


#### Command Example
``` ```
##### 1- Single URL
!phishup-check-urls Urls="https://www.paloaltonetworks.com/cortex/xsoar"

##### 2- URL List
!phishup-check-urls Urls="['https://www.paloaltonetworks.com/cortex/xsoar', 'paloaltonetworks.com']"

##### 3- Comma delimited URLs
!phishup-check-urls Urls="https://www.paloaltonetworks.com/cortex/xsoar, paloaltonetworks.com"


##### Human Readable Output
Clean - Raw Response: {'counterfeitApiResultModel': [{'predicitPhishResult': 'Clean', 'predicitPhishScore': '0.71', 'URL': 'http://paloaltonetworks.com', 'Host': 'paloaltonetworks.com', 'Status': 'active'}]}


### phishup-get-chosen-action
***
Get chosen PhishUp action option from instance


#### Base Command

`!phishup-get-chosen-action`
#### Input
There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PhishUp.Action | String | Chosen PhishUp action like deleting mail or maving mail to spam box | 


#### Command Example
``` ```
`!phishup-get-chosen-action`

#### Human Readable Output

Delete Mail