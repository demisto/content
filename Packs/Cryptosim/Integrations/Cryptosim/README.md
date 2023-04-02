# CRYPTTECH CRYPTOSIM
**CRYPTOSIM meets the SIEM needs of corporations by its unique correlation engine works in memory, capable of hierarchical correlation, supports different correlation techniques, query structure that allows all kinds of data analytics, detects AI based algorithms behavioral anomalies and threat patterns that are not in rule sets.**

From the personal devices we use to the most critical governmental substructures, the awareness of the importance of cyber threats in every segment of the digitalized world and the fact that cyber security must be in all areas of our lives becomes more and more obvious.

The massive attacks on the global scale have clearly demonstrated the importance of taking measures against cyber threats and increasing investments on this area.

CRYPTTECH continues to work towards the goal with the mission of developing new, innovative and indigenous technology and products in the increasingly complex cyber security world. CRYPTTECH provides its unique in-memory correlation capability for its SIEM product with its strong correlation system. CRYPTOSIM collects all logs, detects behavioral differences & anomalies and automatically associates them.

More over it can catch APT (Advanced Persistent Threats). CRYPTTECH achieves high performance values for the SIEM product with its NoSQL structure developed by itself. CRYPTOSIM has become one of the most strategic products for perception of threats with its unique correlation features working with rules and machine learning methods

## What does this pack do?
- Gets all correlations from CRPYTOSIM
- Gets all correlation alerts from CRPYTOSIM
- Creates incidents from correlation alerts

## Use Cases
1. Fetching alerts based on correlations.
2. Getting additional information by command parameters.
3. Searching correlations.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

**Examples:**
1. !cryptosim-get-correlations limit=100 sortType=desc
2. !cryptosim-get-correlationalerts startDate=2022-01-01T12:00:00 endDate=2022-01-01T23:59:59 etc.(shown when command is written)
### cryptosim-get-correlation-alerts
***
The command is used to get correlation alerts.


#### Base Command

`cryptosim-get-correlation-alerts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| startDate | This denotes the start date of the search period. It must be used in all API fields. E.g.: “startDate”: “2021-04-24T12:00:00”. | Required | 
| endDate | This denotes the end date of the search period. It must be used in all API fields. E.g.: endDate: “2021-04-24T24:00:00”. | Required | 
| showSolved | Boolean, show only solved correlations if the parameter is true, otherwise take all correlations. | Optional | 
| crrPluginId | If user want to take specific correlation, can take it when ID of correlation is given as parameter. | Optional | 
| containStr | This is used to search for a word specified in the request. (Contains String) E.g.: “containStr”: “Unsuccessful”. | Optional | 
| risk | The risk level of correlation rules to filter. Default: -1. Default get all. | Optional | 
| srcIPPort | This  used  to  search  the  source  IP address in the request. E.g.: “srcIPPort”: “127.0.0.1”. | Optional | 
| destIPPort | This  used  to  search  the  destination  IP address in the request. E.g.: “dest IPPort”: “127.0.0.1”. | Optional | 
| srcPort | This  is  used  to  filter  the  responses using the source port. E.g.: “srcPort”: “6335”. | Optional | 
| destPort | This  is  used  to  filter  the  responses using the source port. E.g.: “destPort”: “6335”. | Optional | 
| riskOperatorID | risk operator name. It can be equal, greaternumber, greaterorequalnumber, lessnumber, lessnumberorequal, notequal. Default: equal. Default is equal. | Optional | 
| limit | The limit to get how many correlation alerts get. Default: 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CorrelationAlerts.Output | Dictionary | Return StatusCode, Data or ErrorMessage and Outparameters. StatusCode represent html response code. If it is 200, return Data as list of desired Correlation object. If not, return ErrorMessage. OutParameters is empty. | 
