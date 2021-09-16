Run commands on Picus and automate security validation with playbooks.
This integration was integrated and tested with version 3976 of Picus

## Configure Picus on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Picus.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Picus Manager URL |  | True |
    | Picus Refresh Token | The refresh token will be used to generate access token. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### Picus_getAccessToken
***
Generates an access token for api usage. Looks for X-Refresh-Token on header or refresh-token cookie.


#### Base Command

`Picus_getAccessToken`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### Picus_getVectorList
***
Returns the list of the vectors all disabled and enabled ones have optional parameters for pagination.


#### Base Command

`Picus_getVectorList`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| add_user_details | Add vectors' assigned user details to the response. | Optional | 
| page | Requested page number. | Optional | 
| size | Requested data size. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### Picus_getPeerList
***
Returns the peer list with current statuses.


#### Base Command

`Picus_getPeerList`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### Picus_getAttackResults
***
Returns the list of the attack results have optional parameters for filtration.


#### Base Command

`Picus_getAttackResults`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attacker_peer | Untrusted peer name. | Required | 
| victim_peer | Trusted peer name. | Required | 
| days | Set days parameter. Default is 3. | Optional | 
| result | This setting can only be insecure,secure and all. Default is all. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### Picus_runAttacks
***
Schedules a single attack on requested vector.


#### Base Command

`Picus_runAttacks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_ids | Threat ID list ("111,222,333,...") or single threat ID can be given. | Required | 
| attacker_peer | Untrusted peer name. | Required | 
| victim_peer | Trusted peer name. | Required | 
| variant | Example variant=HTTP. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### Picus_getThreatResults
***
Returns the list of the attack results of a single threat have optional parameters for filtration.


#### Base Command

`Picus_getThreatResults`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_ids | Threat ID list ("111,222,333,...") or single threat ID can be given. | Required | 
| attacker_peer | Untrusted peer name. | Required | 
| victim_peer | Trusted peer name. | Required | 
| variant | Example variant=HTTP. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### Picus_setParamPB
***
Set parameter on playbook.


#### Base Command

`Picus_setParamPB`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attacker_peer | Untrusted peer name. | Required | 
| victim_peer | Trusted peer name. | Required | 
| variant | Example variant=HTTP. | Required | 
| mitigation_product | Products info of the mitigation. | Required | 
| days | Set days parameter. Default is 3. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### filter-insecure-attacks
***
Filter insecure attacks on playbook.


#### Base Command

`filter-insecure-attacks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threatinfo | Threat id and result combine. Used for playbook. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### Picus_getMitigationList
***
Returns the list of the mitigations of threats have optional parameters for filtration, this route may not be used associated with your license.


#### Base Command

`Picus_getMitigationList`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_ids | Threat ID list ("111,222,333,...") or single threat ID can be given. | Required | 
| product | Products info of the mitigation. This parameter can be Check Point NGFW, ForcepointNGFW, McAfee IPS, PaloAlto IPS, SourceFire IPS, TippingPoint, F5 BIG-IP, Fortigate WAF, FortiWeb, Fortigate IPS, Snort, CitrixWAF, and ModSecurity. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### Picus_getVectorCompare
***
Makes a comparison of the given vector's results.


#### Base Command

`Picus_getVectorCompare`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attacker_peer | Untrusted peer name. | Required | 
| victim_peer | Trusted peer name. | Required | 
| days | Set days parameter. Default is 3. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


