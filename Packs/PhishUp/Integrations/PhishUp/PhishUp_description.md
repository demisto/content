 ## PhishUp Real Time Cyber Threat Analytics

If you don't have [PhishUp](https://phishup.co) Api Key 
please create account on PhishUp and get an Api Key. 
Also you can visit and test [PhishUp Web Demo](https://phishup.co).

If you have any question feel free to concat us: [info@phishup.com](info@phishup.co)


------
## Configure PhishUp on Cortex XSOAR

1. PhishUp Integration Requirements.

| **Parameter**           | **Required** | **Description**                        |
|-------------------------|--------------|----------------------------------------|
| Password (Api Key)      | True         | Enter your PhishUp Api Key as Password |
| PhishUp Playbook Action | True         | PhishUp Playbook Mail Action           |

2. Click **Test** to Api Key and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### phishup-investigate-bulk-url
***
Get URLs reputation


#### Base Command

`!phishup-investigate-bulk-url`
#### Input

| **Argument Name** | **Description**                     | **Required** | **Usage** |
| --- |-------------------------------------| --- | --- |
| Urls | Url List for sending to PhishUp Api | Required | Sending List of Url (Single or Bulk)


#### Context Output

| **Path**               | **Type** | **Description**                       | **Results** |
|------------------------| --- |---------------------------------------| --- |
| PhishUp.Results        | String | PhishUp Url Investigating Result List | Result List
| PhishUp.AverageResult  | String | If any harmfull URL in list this value will return "Phish" otherwhise will return "Clean", if any error happens will return "Error" | Clean, Phish, Error


PhishUp.Results contains raw result list. 
PhishUp.AverageResult created for playbook usage.


#### Command Examples
##### 1- Single URL
`!phishup-investigate-bulk-url Urls="https://www.paloaltonetworks.com/cortex/xsoar"`

##### 2- URL List
`!phishup-investigate-bulk-url Urls="[\"https://www.paloaltonetworks.com/cortex/xsoar\", \"paloaltonetworks.com\"]"`
##### Human Readable Output
`
{
"Results": [
{
"IncomingUrl": "https://www.paloaltonetworks.com/cortex/xsoar",
"IsRouted": false,
"PhishUpScore": "1.00",
"PhishUpStatus": "Clean",
"Url": "www.paloaltonetworks.com"
},
{
"IncomingUrl": "paloaltonetworks.com",
"IsRouted": true,
"PhishUpScore": "1.00",
"PhishUpStatus": "Clean",
"Url": "www.paloaltonetworks.com"
}
]
}
`

### phishup-investigate-url
***
Get Url Reputation

#### Base Command

`phishup-investigate-url`
#### Input

| **Argument Name** | **Description**                       | **Required** | **Usage** |
| --- |---------------------------------------| --- | --- |
| Url | Single URL for sending to PhishUp Api | Required | Send single URL string


#### Context Output

| **Path**       | **Type** | **Description**                   | **Results** |
|----------------| --- |-----------------------------------| --- |
| PhishUp.Result | String | PhishUp Url Investigating Result  | response types "Clean", "Phish", "Error"
| PhishUp.Score  | String | Phishup Engine Result Class Score | Number


PhishUp.Result contains raw result. 
PhishUp.Score is score for predicted class.


#### Command Examples
`!phishup-investigate-url Url="https://www.paloaltonetworks.com/cortex/xsoar"`

##### Human Readable Output
`
{'IncomingUrl': 'https://www.paloaltonetworks.com/cortex/xsoar', 'Url': 'www.paloaltonetworks.com', 'IsRouted': False, 'PhishUpStatus': 'Clean', 'PhishUpScore': '1.00'}
`

### phishup-get-chosen-action
***
Get chosen PhishUp Playbook action option from instance


#### Base Command

`!phishup-get-chosen-action`
#### Input
There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description**                                                              |
| --- | --- |------------------------------------------------------------------------------|
| PhishUp.Action | String | Chosen PhishUp Playbook action like deleting mail or maving mail to spam box | 


#### Command Example

`!phishup-get-chosen-action`

#### Human Readable Output

Chosen Action: Move to SPAM