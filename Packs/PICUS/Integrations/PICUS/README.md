Continuous Breach And Attack Simulation

## Configure PICUS in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| PICUS URL | For example : https://192.168.100.100/ | True |
| API Key - Refresh Token | Picus Interface  - SETTINGS -  ADVANCED - API TOKEN - Generate and Show Token | True |
| Trust any certificate (not secure) |  |  |
| Use system proxy settings |  |  |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### picus-vector-compare

***
Attack Result - Makes a comparison of the given vector's results. Example Command: !picus-vector-compare begin_date=2020-01-20 end_date=2021-01-20 trusted=Trusted_Peer1 untrusted=Untrusted_Peer1

#### Base Command

`picus-vector-compare`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| begin_date | Result begin date. | Required | 
| end_date | Result end date. | Required | 
| trusted | Victem Peer. | Required | 
| untrusted | Attacker Peer. | Required | 

#### Context Output

There is no context output for this command.
### picus-attack-result-list

***
Returns the list of the attack results have optional parameters for pagination and filtration. \nExample Command:\n !picus-attack-result-list attack_result=insecure begin_date=2020-01-01 end_date=2020-09-05  vector1=Trusted-Peer1 vector2=Untrusted-Peer1

#### Base Command

`picus-attack-result-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack_result | Attack results that should be filtered. Secure or Insecure. Possible values are: secure, insecure. Default is insecure. | Required | 
| begin_date | Threat release date filter start of the date range. | Required | 
| console_output_info | Default: false -  Process Results of Scenario Details have console output information which can be in large sizes so this data is disabled by default. Default is False. | Optional | 
| end_date | 	 string Default: "Today's date formatted YYYY-mm-dd" Threat release date filter end of the date range if a begin date is given and end date not, default will be used. | Required | 
| from_time | Default: "null" allowed time formats RFC822, RFC822Z, RFC1123, RFC1123Z, RFC850, RFC3339. Default is null. | Optional | 
| page | Default: 1 Requested page number. Default is 1. | Optional | 
| size | Default: 50 Requested data size. Default is 50. | Optional | 
| threat_parameters | "threat_parameters": { "begin_date": "2018-10-29", "categories": [ [ "Malicious Code" ], [ "Attack Scenario", "Defense Evasion", "Indicator Removal from Tools" ] ],. | Optional | 
| vector1 |  Array of objects (PeerPairParams) Vectors.(Trusted Peer). | Required | 
| vector2 |  Array of objects (PeerPairParams) Vectors.(Untrusted Peer). | Required | 

#### Context Output

There is no context output for this command.
### picus-specific-threats-results

***
Returns the list of the attack results of a single threat have optional parameters for pagination and filtration. Example Command: !picus-specific-threats-results threat_id=666059

#### Base Command

`picus-specific-threats-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | CVE code of the threat to be filtered. | Optional | 
| md5 | The md5 of the threat. | Optional | 
| page | integer &lt;int64&gt; -  Default: 1 Requested page number. Default is 1. | Optional | 
| sha256 | SHA256 hash of the threat. | Optional | 
| size | integer &lt;int64&gt; - Default: 50 Requested data size. Default is 50. | Optional | 
| threat_id | integer &lt;int64&gt; PID of the threat. | Required | 

#### Context Output

There is no context output for this command.
### picus-peer-list

***
Returns the peer list with current statuses

#### Base Command

`picus-peer-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### picus-attack-all-vectors

***
Schedules given attack on all possible vectors

#### Base Command

`picus-attack-all-vectors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | Example: threat_id=100682 PID of the threat. | Required | 

#### Context Output

There is no context output for this command.
### picus-attack-single

***
Schedules a single attack on requested vector

#### Base Command

`picus-attack-single`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | Example: threat_id=666059 PID of the threat. | Required | 
| variant | Example: variant=HTTP. | Required | 
| vector1 | Example: trusted=Trusted-Peer-Name Trusted peer name, if type is overall, it is not necessary. | Required | 
| vector2 | Example: untrusted=Untrusted-Peer-Name Untrusted peer name, if type is overall, it is not necessary. | Required | 

#### Context Output

There is no context output for this command.
### picus-trigger-update

***
Triggers the update mechanism manually, returns if the update-command is taken successfully

#### Base Command

`picus-trigger-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### picus-version

***
Returns the current version and the update time config

#### Base Command

`picus-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### picus-mitigation-list

***
Returns the list of the mitigations of threats\nhave optional parameters for pagination and filtration, this route may not be used associated with your license. Example Command: !picus-mitigation-list begin_date=2021-01-01 end_date=2021-02-01 threat_id=528370 products="McAfee IPS" signature_id=0x40208a00

#### Base Command

`picus-mitigation-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| begin_date | Threat release date filter start of the date range. | Required | 
| end_date | Default: "Today's date formatted YYYY-mm-dd" Threat release date filter end of the date range if a begin date is given and end date not, default will be used. | Required | 
| page | integer &lt;int64&gt; Default: 1 Requested page number. Default is 1. | Optional | 
| products | Array of strings - Products info of the mitigation. Possible values are: , . | Required | 
| signature_id | ID of the signature. | Required | 
| size | integer &lt;int64&gt; - Default: 50 Requested data size. Default is 50. | Optional | 
| threat_id | integer &lt;int64&gt; -  PID of the threat. | Required | 

#### Context Output

There is no context output for this command.
### picus-mitre-matrix

***
Returns the mitre matrix metadata takes no parameters

#### Base Command

`picus-mitre-matrix`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### picus-sigma-rules-list

***
Returns the list of the sigma rules of scenario actions have optional parameters for pagination and filtration, this route may not be used associated with your license

#### Base Command

`picus-sigma-rules-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| size | Size of Displayed Rule. Default is 100. | Optional | 
| page | Page of Displayed Rule. Default is 1. | Optional | 

#### Context Output

There is no context output for this command.
### picus-vector-list

***
Returns the list of the vectors all disabled and enabled ones have optional parameters for pagination

#### Base Command

`picus-vector-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| add_user_details | boolean - Add vectors' assigned user details to the response. Default is True. | Optional | 
| page | Default: 1 Requested page number. Default is 1. | Optional | 
| size | Default: 50 Requested data size. Default is 50. | Optional | 

#### Context Output

There is no context output for this command.