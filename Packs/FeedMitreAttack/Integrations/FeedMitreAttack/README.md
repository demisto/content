Deprecated. Use ***MITRE ATT&CK v2*** instead.

Use the MITRE ATT&CK Feed integration to fetch indicators from MITRE ATT&CK.
For more information click [here](https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via).

## Configure MITRE ATT&CK Feed on XSOAR


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| includeAPT | This option will also create indicators using APT / actor name references if they are part of a MITRE Intrusion Set | False |
| feedReputation | The indicator reputation (defaults to 'None'). | False |
| feedReliability | The source's reliability. | True |
| tlp_color | The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp | False |
| feedExpirationPolicy | The feed's expiration policy. | False |
| feedExpirationInterval | The interval after which the feed expires. | False |
| feedFetchInterval | The feed fetch interval. | False |
| feedBypassExclusionList | Whether to bypass exclusion list. | False |
| insecure | Whether to trust any certificate (not secure). | False |
| proxy | Whether to use the system proxy settings. | False |


#### Feed timeouts:
MITRE enforce a rate limit for connecting to their taxii server. Ensure that your fetch interval is reasonable, otherwise you will receive connection errors.

## Commands
You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Get Indicators
***
Gets the indicators from MITRE ATT&CK.

Note: This command does not create indicators within Cortex XSOAR.

##### Base Command

`mitre-get-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. The default value is 10. | Optional | 
| raw | Enabling raw will also output the raw content of each indicator | Optional | 


##### Context Output

The context is output as:

- MITRE *(dict)*
    - ATT&CK *(list)*

Each item in the "ATT&CK" list contains the following keys:
- fields *(any fields that the indicator will attempt to map into the indicator)*
- rawJSON *(the raw JSON of the indicator)*
- score *(the indicator score)*
- type *(the type of indicator - will always be "MITRE ATT&CK")*
- value *(the indicator value, for example "T1134")*
     

##### Command Example
```!mitre-get-indicators limit=2```


##### Human Readable Output
### MITRE ATT&CK Indicators:
| Value | Score| Type |
| ----- | ---- | ---- |
| T1531 | 0 | MITRE ATT&CK |
| T1506 | 0 | MITRE ATT&CK |


### MITRE reputation
***
Lookup the reputation of an indicator from the local indicators within XSOAR.

Note: This does not connect outbound to get the reputation score

##### Base Command

`mitre-reputation`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator | Indicator to lookup | Required |  


##### Context Output

The context is output as:

- DBotScore
- MITRE *(dict)*
    - ATT&CK *(list)* 

Each item in the "ATT&CK" list contains the customFields that are mapped into the indicator (each beginning with 'mitre')
     

##### Command Example
```!mitre-reputation indicator=T1134```


##### Human Readable Output
### MITRE ATT&CK Indicators:
## T1134:
### attack-pattern
Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token. For example, Microsoft promotes the use of access tokens as a security best practice. Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command <code>runas</code>.(Citation: Microsoft runas)
Adversaries may use access tokens to operate under a different user or system security context to perform actions and evade detection. An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.(Citation: Pentestlab Token Manipulation)
Access tokens can be leveraged by adversaries through three methods:(Citation: BlackHat Atkinson Winchester Token Manipulation)
Token Impersonation/Theft - An adversary creates a new access token that duplicates an existing token using <code>DuplicateToken(Ex)</code>. The token can then be used with <code>ImpersonateLoggedOnUser</code> to allow the calling thread to impersonate a logged on user's security context, or with <code>SetThreadToken</code> to assign the impersonated token to a thread. This is useful for when the target user has a non-network logon session on the system.
Create Process with a Token - An adversary creates a new access token with <code>DuplicateToken(Ex)</code> and uses it with <code>CreateProcessWithTokenW</code> to create a new process running under the security context of the impersonated user. This is useful for creating a new process under the security context of a different user.
Make and Impersonate Token - An adversary has a username and password but the user is not logged onto the system. The adversary can then create a logon session for the user using the <code>LogonUser</code> function. The function will return a copy of the new session's access token and the adversary can use <code>SetThreadToken</code> to assign the token to a thread.
Any standard user can use the <code>runas</code> command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account.
Metasploit’s Meterpreter payload allows arbitrary token manipulation and uses token impersonation to escalate privileges.(Citation: Metasploit access token) The Cobalt Strike beacon payload allows arbitrary token impersonation and can also create tokens. (Citation: Cobalt Strike Access Token)
_____

### course-of-action
Access tokens are an integral part of the security system within Windows and cannot be turned off. However, an attacker must already have administrator level access on the local system to make full use of this technique; be sure to restrict users and accounts to the least privileges they require to do their job.
Any user can also spoof access tokens if they have legitimate credentials. Follow mitigation guidelines for preventing adversary use of Valid Accounts. Limit permissions so that users and user groups cannot create tokens. This setting should be defined for the local system account only. GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Create a token object. (Citation: Microsoft Create Token) Also define who can create a process level token to only the local and network service through GPO: Computer Configuration > [Policies] > Windows Settings > Security Settings > Local Policies > User Rights Assignment: Replace a process level token. (Citation: Microsoft Replace Process Token)
Also limit opportunities for adversaries to increase privileges by limiting Privilege Escalation opportunities.



### MITRE Show Feeds
***
Displays the available feeds from the MITRE taxii service.

##### Base Command

`mitre-showfeeds`
##### Input

There are no inputs  

##### Context Output

There is no context output


##### Command Example
```!mitre-showfeeds```


##### Human Readable Output
### MITRE ATT&CK Feeds:
| Name | ID |
| ---- | --- |
| Enterprise ATT&CK | 95ecc380-afe9-11e4-9b6c-751b66dd541e |
| PRE-ATT&CK | 062767bd-02d2-4b72-84ba-56caef0f8658 |
| Mobile ATT&CK | 2f669986-b40b-4423-b720-4396ca6a462b |



### MITRE Search feeds
***
Performs a text search of name and description in the local MITRE ATT&CK indicators.

Note: This does not connect outbound to get the reputation score

##### Base Command

`mitre-search-indicators`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | The search word | Required |  
| casesensitive | Whether or not to use case sensitivity | Optional (defaults to False)

##### Context Output

The context is output as:

- indicators *(list)*

Each item in the "indicators" list contains the 'id' and 'value' fields of the indicators found.
     

##### Command Example
```!mitre-search-indicators search=APT12```


##### Human Readable Output
### MITRE Indicator search:
| Name |
| ---- |
| APT12 |
| RIPTIDE |

Note: the table outputs links to the indicator in XSOAR.