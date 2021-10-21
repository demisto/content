Run commands on Picus and automate security validation with playbooks.
This integration was integrated and tested with version 3976 of Picus

## Configure Picus on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Picus.

![image](./../../doc_files/search_integration.png)

3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Picus Manager URL |  | True |
    | Picus Refresh Token | The refresh token will be used to generate access token. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

![image](./../../doc_files/test_integration.png)

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### picus-get-access-token
***
Generates an access token for API usage. This function used for other functions inner authentication mechanism. Looks for X-Refresh-Token on the header or refresh-token cookie.




#### Base Command

`picus-get-access-token`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.



### picus-get-vector-list
***
Returns the vector list from PICUS. These vectors can be used for automation processes.


#### Base Command

`picus-get-vector-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| add_user_details | Add vectors' assigned user details to the response. | Optional | 
| page | Requested page number. | Optional | 
| size | Requested data size. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!picus-get-vector-list```

#### Human Readable Output

|name|trusted|untrusted|is_disabled|type|
|---|---|---|---|---|
| Picus_Attacker_1 - Win10-Det1 | Win10-Det1 | Picus_Attacker_1 | true | Endpoint |
| Picus_Attacker_2 - Win10-Det2 | Win10-Det2 | Picus_Attacker_2 | true | Endpoint |



### picus-get-peer-list
***
Returns the peer list with current statuses. These peers also can be seen on the **PICUS Panel ->Settings-> Peers**.

![image](./../../doc_files/peer_page.png)


#### Base Command

`picus-get-peer-list`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!picus-get-peer-list```

#### Human Readable Output

|name|registered_ip|type|is_alive|
|---|---|---|---|
| Picus_Attacker_1 | x.x.x.x | Network | true |
| Picus_Attacker_2 | x.x.x.x | Network | true |
| Win10-Det2 | x.x.x.x | Endpoint | true |



### picus-get-attack-results
***
In the Picus, all attacks are carried out with the logic of the attacker and the victim. This command returns the list of the attack results on specified peers. Time range and result status can be given.


#### Base Command

`picus-get-attack-results`
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
```!picus-get-attack-results attacker_peer="Picus_Attacker_1" victim_peer="net1-det1" days=1 result="insecure"```

#### Human Readable Output

|begin_time|end_time|string|threat_id|threat_name|
|---|---|---|---|---|
| 2021-09-16T23:59:54.738644627Z | 2021-09-16T23:59:54.753408649Z | Insecure | 206450 | HTML5 Web Storage Sensitive Data Exposure |
| 2021-09-16T23:52:52.022470123Z | 2021-09-16T23:52:52.077736344Z | Insecure | 206111 | Zeus PandaBanker Trojan .EXE File Download Variant-11 |



### picus-run-attacks
***
In the Picus, all attacks are carried out with the logic of the attacker and the victim. This command schedules a single attack on the requested vector.


#### Base Command

`picus-run-attacks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_ids | Threat ID list ("111,222,333,...") or single threat ID can be given. | Required | 
| attacker_peer | Untrusted peer name. | Required | 
| victim_peer | Trusted peer name. | Required | 
| variant | This parameter can be HTTP or HTTPS. Example variant=HTTP | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!picus-run-attacks attacker_peer="Picus_Attacker_1" victim_peer="net1-det1" threat_ids="881728,879812,798283" variant="HTTP"```

#### Human Readable Output

|threat_id|result|
|---|---|
| 881728 | success |
| 879812 | success |
| 798283 | success |



### picus-get-threat-results
***
Returns the list of the attack results of a single threat have optional parameters for filtration.


#### Base Command

`picus-get-threat-results`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_ids | Threat ID list ("111,222,333,...") or single threat ID can be given. | Required | 
| attacker_peer | Untrusted peer name. | Required | 
| victim_peer | Trusted peer name. | Required | 
| variant | This parameter can be HTTP or HTTPS. Example variant=HTTP | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!picus-get-threat-results attacker_peer="Picus_Attacker_1" victim_peer="net1-det1" variant="HTTP" threat_ids="562172"```

#### Human Readable Output

|threat_id|result|l1_category|last_time|status|
|---|---|---|---|---|
| 562172 | Secure | Vulnerability Exploitation | 2021-09-16T13:26:00.932298Z | success |



### picus-set-paramPB
***
Set parameter on the playbook. (This command is only used on playbook)


#### Base Command

`picus-set-paramPB`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attacker_peer | Untrusted peer name. | Required | 
| victim_peer | Trusted peer name. | Required | 
| variant | This parameter can be HTTP or HTTPS. Example variant=HTTP | Required | 
| mitigation_product | Products info of the mitigation. This parameter can be Check Point NGFW, ForcepointNGFW, McAfee IPS, PaloAlto IPS, SourceFire IPS, TippingPoint, F5 BIG-IP, Fortigate WAF, FortiWeb, Fortigate IPS, Snort, CitrixWAF, and ModSecurity. | Required | 
| days | Set days parameter. Default is 3. | Optional |



### filter-insecure-attacks
***
Filter insecure attacks on the playbook. (This command is only used on playbook)


#### Base Command

`filter-insecure-attacks`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threatinfo | Threat id and result combine. Used for playbook. | Required | 



### picus-get-mitigation-list
***
Returns the list of the mitigations of threats have optional parameters for filtration, this route may not be used associated with your license.


#### Base Command

`picus-get-mitigation-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_ids | Threat ID list ("111,222,333,...") or single threat ID can be given. | Required | 
| product | Products info of the mitigation. This parameter can be Check Point NGFW, ForcepointNGFW, McAfee IPS, PaloAlto IPS, SourceFire IPS, TippingPoint, F5 BIG-IP, Fortigate WAF, FortiWeb, Fortigate IPS, Snort, CitrixWAF, and ModSecurity. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!picus-get-mitigation-list threat_ids="103847" product="Snort"```

#### Human Readable Output

|threat_id|signature_id|signature_name|
|---|---|---|
| 103847 | 1.2025644.1 | ET TROJAN Possible Metasploit Payload Common Construct Bind_API (from server) |
| 103847 | 1.44728.3 | INDICATOR-COMPROMISE Meterpreter payload download attempt |



### picus-get-vector-compare
***
Makes a comparison of the given vector's results.


#### Base Command

`picus-get-vector-compare`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attacker_peer | Untrusted peer name. | Required | 
| victim_peer | Trusted peer name. | Required | 
| days | Set days parameter. Default is 3. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!picus-get-vector-compare attacker_peer="Picus_Attacker_1" victim_peer="net1-det1"```

#### Human Readable Output

|status|threat_id|name|
|---|---|---|
| secure | 204923 | XSS Evasion via HTML Encoding Variant-4 |
| insecure | null | null |
| secure_to_insecures | null | null |
| insecure_to_secures | null | null |



### picus-version
***
Returns the current Picus version and the update time config.


#### Base Command

`picus-version`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!picus-version```

#### Human Readable Output

|version|update_time|last_update_date|
|---|---|---|
| 4025 | 0 | 20.10.2021 |



### picus-trigger-update
***
Triggers the Picus product update mechanism manually.


#### Base Command

`picus-trigger-update`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!picus-trigger-update```

#### Human Readable Output

|data|success|
|---|---|
| true | true |